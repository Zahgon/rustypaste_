use crate::error::{self, Error};
use axum::http::HeaderMap;
use std::time::Duration;

/// Custom HTTP header for expiry dates.
pub const EXPIRE: &str = "expire";

/// Custom HTTP header to override filename.
const FILENAME: &str = "filename";

/// Parses the expiry date from the [`custom HTTP header`](EXPIRE).
pub fn parse_expiry_date(headers: &HeaderMap, time: Duration) -> Result<Option<u128>, Error> {
    if let Some(expire_time) = headers.get(EXPIRE).and_then(|v| v.to_str().ok()) {
        let expire_time = humantime::parse_duration(expire_time).map_err(error::internal)?;
        Ok(time.checked_add(expire_time).map(|t| t.as_millis()))
    } else {
        Ok(None)
    }
}

/// Parses the filename from the header.
pub fn parse_header_filename(headers: &HeaderMap) -> Result<Option<String>, Error> {
    if let Some(file_name) = headers.get(FILENAME).and_then(|v| v.to_str().ok()) {
        Ok(Some(file_name.to_string()))
    } else {
        Ok(None)
    }
}

/// Parsed `Content-Disposition` header of a multipart field.
///
/// Aims to parse the file data from multipart body.
///
/// e.g. `Content-Disposition: form-data; name="field_name"; filename="filename.jpg"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDisposition {
    form_data: bool,
    name: Option<String>,
    file_name: Option<String>,
}

impl ContentDisposition {
    /// Parses a raw header value, returning `None` when it is malformed.
    ///
    /// Parameter names are matched case-insensitively and values may be tokens or quoted
    /// strings with backslash escapes. Only the first `name` and `filename` are kept.
    pub fn parse(value: &str) -> Option<Self> {
        let (disposition, mut rest) = match value.split_once(';') {
            Some((disposition, rest)) => (disposition.trim(), rest),
            None => (value.trim(), ""),
        };
        if disposition.is_empty() {
            return None;
        }
        let mut content_disposition = Self {
            form_data: disposition.eq_ignore_ascii_case("form-data"),
            name: None,
            file_name: None,
        };
        loop {
            rest = rest.trim_start_matches([' ', '\t', ';']);
            if rest.is_empty() {
                break;
            }
            let (param, after) = rest.split_once('=')?;
            let param = param.trim().to_ascii_lowercase();
            let after = after.trim_start();
            let (value, remaining) = if let Some(quoted) = after.strip_prefix('"') {
                let mut value = String::new();
                let mut chars = quoted.char_indices();
                let mut end = None;
                while let Some((index, c)) = chars.next() {
                    match c {
                        '\\' => value.push(chars.next()?.1),
                        '"' => {
                            end = Some(index + 1);
                            break;
                        }
                        c => value.push(c),
                    }
                }
                (value, &quoted[end?..])
            } else {
                let end = after.find(';').unwrap_or(after.len());
                (after[..end].trim().to_string(), &after[end..])
            };
            match param.as_str() {
                "name" if content_disposition.name.is_none() => {
                    content_disposition.name = Some(value)
                }
                "filename" if content_disposition.file_name.is_none() => {
                    content_disposition.file_name = Some(value)
                }
                _ => {}
            }
            rest = remaining;
        }
        Some(content_disposition)
    }

    /// Returns `true` if the disposition type is `form-data`.
    pub fn is_form_data(&self) -> bool {
        self.form_data
    }

    /// Returns the `name` parameter if it exists.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Checks if the content disposition is a form data
    /// and has the field `field_name`.
    pub fn has_form_field(&self, field_name: &str) -> bool {
        self.form_data && self.name.as_deref() == Some(field_name)
    }

    /// Parses the file name from parameters if it exists.
    pub fn get_file_name(&self) -> Result<&str, Error> {
        self.file_name
            .as_deref()
            .filter(|file_name| !file_name.is_empty())
            .ok_or_else(|| error::bad_request("file data not present"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;
    use axum::http::header::{HeaderName, HeaderValue};
    use std::thread;

    #[test]
    fn test_content_disposition() -> Result<(), Error> {
        let content_disposition =
            ContentDisposition::parse(r#"form-data; name="file"; filename="x.txt""#)
                .expect("cannot parse content disposition");
        assert!(content_disposition.has_form_field("file"));
        assert!(!content_disposition.has_form_field("test"));
        assert_eq!("x.txt", content_disposition.get_file_name()?);

        let content_disposition = ContentDisposition::parse(r#"attachment; name="file""#)
            .expect("cannot parse content disposition");
        assert!(!content_disposition.has_form_field("file"));
        assert!(content_disposition.get_file_name().is_err());
        Ok(())
    }

    #[test]
    fn test_expiry_date() -> Result<(), Error> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(EXPIRE),
            HeaderValue::from_static("5ms"),
        );
        let time = util::get_system_time()?;
        let expiry_time = parse_expiry_date(&headers, time)?.unwrap_or_default();
        assert!(expiry_time > util::get_system_time()?.as_millis());
        thread::sleep(Duration::from_millis(10));
        assert!(expiry_time < util::get_system_time()?.as_millis());
        Ok(())
    }
}
