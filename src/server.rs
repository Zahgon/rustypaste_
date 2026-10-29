use crate::auth::{self, AuthToken, DeleteToken, Grants, Protected};
use crate::config::{Config, LandingPageConfig, TokenType};
use crate::error::{self, Error};
use crate::file::Directory;
use crate::header::{self, ContentDisposition};
use crate::mime as mime_util;
use crate::paste::{Paste, PasteType, PASTE_VARIANTS_LIST};
use crate::util::{self, safe_path_join};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{
    AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, FORWARDED, HOST,
    LOCATION, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{middleware, Extension, Router};
use base64::Engine;
use byte_unit::{Byte, UnitType};
use mime::{Mime, TEXT_PLAIN_UTF_8};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{Duration, UNIX_EPOCH};
use tower::ServiceExt;
use tower_http::services::ServeFile;
use uts2ts;

/// Host used for upload URLs when a request names none, as the original server did.
const DEFAULT_HOST: &str = "localhost:8080";

/// Shared state of the HTTP server.
#[derive(Clone, Debug)]
pub struct AppState {
    /// Configuration, replaced in place when the configuration file changes.
    pub config: Arc<RwLock<Config>>,
    /// HTTP client for remote uploads.
    pub client: reqwest::Client,
}

impl AppState {
    /// Acquires the current configuration.
    pub fn config(&self) -> Result<RwLockReadGuard<'_, Config>, Error> {
        self.config
            .read()
            .map_err(|_| error::internal("cannot acquire config"))
    }
}

/// Connection information resolved from the `Forwarded`, `X-Forwarded-*` and `Host` headers.
#[derive(Debug)]
pub(crate) struct ConnectionInfo {
    scheme: String,
    host: String,
    realip_remote_addr: Option<String>,
}

impl ConnectionInfo {
    /// Resolves the connection information of a request.
    pub(crate) fn new(parts: &Parts) -> Self {
        let headers = &parts.headers;
        let mut host = None;
        let mut scheme = None;
        let mut realip_remote_addr = None;
        for (name, value) in headers
            .get_all(FORWARDED)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .flat_map(|v| v.split(','))
            .filter_map(|pair| pair.trim().split_once('='))
        {
            let unquote = |v: &str| v.trim().trim_matches('"').to_string();
            match name.trim().to_lowercase().as_str() {
                "for" => {
                    realip_remote_addr.get_or_insert_with(|| bare_address(&unquote(value)));
                }
                "proto" => {
                    scheme.get_or_insert_with(|| unquote(value));
                }
                "host" => {
                    host.get_or_insert_with(|| unquote(value));
                }
                _ => {}
            }
        }
        let first_value = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_string())
        };
        let scheme = scheme
            .or_else(|| first_value("x-forwarded-proto"))
            .or_else(|| parts.uri.scheme_str().map(str::to_string))
            .unwrap_or_else(|| String::from("http"));
        let host = host
            .or_else(|| first_value("x-forwarded-host"))
            .or_else(|| {
                headers
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            })
            .or_else(|| parts.uri.authority().map(|v| v.to_string()))
            .unwrap_or_else(|| String::from(DEFAULT_HOST));
        let realip_remote_addr = realip_remote_addr
            .or_else(|| first_value("x-forwarded-for"))
            .or_else(|| {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ConnectInfo(addr)| addr.ip().to_string())
            });
        Self {
            scheme,
            host,
            realip_remote_addr,
        }
    }

    /// Returns the real IP address of the client, if known.
    pub(crate) fn realip_remote_addr(&self) -> Option<&str> {
        self.realip_remote_addr.as_deref()
    }
}

/// Removes the port and IPv6 square brackets from a peer specification.
fn bare_address(value: &str) -> String {
    if value.starts_with('[') {
        value
            .split("]:")
            .next()
            .map(|v| v.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or(value)
            .to_string()
    } else {
        value.split(':').next().unwrap_or(value).to_string()
    }
}

/// Returns the percent-decoded file name of a `/{file}` request.
fn requested_file(uri: &Uri) -> String {
    let segment = uri.path().strip_prefix('/').unwrap_or_default();
    percent_decode_str(segment).decode_utf8_lossy().into_owned()
}

/// Extract password from Authorization header.
///
/// Supports Basic Auth (`Basic base64(user:pass)`) and Bearer tokens (`Bearer <token>`).
fn extract_password_from_auth(auth_header: &str) -> Option<String> {
    if let Some(basic) = auth_header.strip_prefix("Basic ") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(basic)
            .ok()?;
        let creds = String::from_utf8(bytes).ok()?;
        creds.split_once(':').map(|(_, p)| p.to_owned())
    } else {
        auth_header
            .strip_prefix("Bearer ")
            .map(|bearer| bearer.to_owned())
    }
}

/// Returns a `302 Found` response redirecting to `location`.
fn found(location: &str) -> Result<Response, Error> {
    let location = HeaderValue::from_str(location).map_err(error::internal)?;
    Ok((StatusCode::FOUND, [(LOCATION, location)]).into_response())
}

/// Returns a `200 OK` response carrying `body` without a content type.
fn plain_ok(body: impl Into<Body>) -> Response {
    Response::new(body.into())
}

/// Shows the landing page.
#[allow(deprecated)]
async fn index(State(state): State<AppState>) -> Result<Response, Error> {
    let mut config = state.config()?.clone();
    let redirect = found(env!("CARGO_PKG_HOMEPAGE"));
    if config.server.landing_page.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.text = config.server.landing_page;
        }
    }
    if config.server.landing_page_content_type.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.content_type = config.server.landing_page_content_type;
        }
    }
    if let Some(mut landing_page) = config.landing_page {
        if let Some(file) = landing_page.file {
            landing_page.text = fs::read_to_string(file).ok();
        }
        match landing_page.text {
            Some(page) => {
                let content_type = HeaderValue::from_str(
                    &landing_page
                        .content_type
                        .unwrap_or(TEXT_PLAIN_UTF_8.to_string()),
                )
                .map_err(error::internal)?;
                Ok(([(CONTENT_TYPE, content_type)], page).into_response())
            }
            None => redirect,
        }
    } else {
        redirect
    }
}

/// File serving options (i.e. query parameters).
#[derive(Debug, Deserialize)]
struct ServeOptions {
    /// If set to `true`, change the MIME type to `application/octet-stream` and force downloading
    /// the file.
    download: bool,
}

/// Answers `GET /{file}`: the version and list endpoints, or a file from the upload directory.
async fn get_file(
    State(state): State<AppState>,
    Extension(grants): Extension<Grants>,
    request: Request,
) -> Result<Response, Error> {
    let file = requested_file(request.uri());
    match file.as_str() {
        "version" | "list" if !grants.contains(TokenType::Auth) => {
            let (parts, _) = request.into_parts();
            auth::log_unauthorized(&parts);
            Err(auth::unauthorized_error())
        }
        "version" => version(&state),
        "list" => list(&state),
        _ => serve(State(state), request).await,
    }
}

/// Serves a file from the upload directory.
async fn serve(State(state): State<AppState>, request: Request) -> Result<Response, Error> {
    let file = requested_file(request.uri());
    let options = request
        .uri()
        .query()
        .and_then(|query| serde_urlencoded::from_str::<ServeOptions>(query).ok());
    let (path, paste_type, response_config) = {
        let config = state.config()?;
        let mut path = util::glob_match_file(safe_path_join(&config.server.upload_path, &file)?)?;
        let mut paste_type = PasteType::File;
        if !path.exists() || path.is_dir() {
            for type_ in &[
                PasteType::Url,
                PasteType::Oneshot,
                PasteType::OneshotUrl,
                PasteType::ProtectedFile,
            ] {
                let alt_path = safe_path_join(type_.get_path(&config.server.upload_path)?, &file)?;
                let alt_path = util::glob_match_file(alt_path)?;
                if alt_path.exists()
                    || path.file_name().and_then(|v| v.to_str()) == Some(&type_.get_dir())
                {
                    path = alt_path;
                    paste_type = *type_;
                    break;
                }
            }
        }
        (path, paste_type, config.clone())
    };
    if !path.is_file() || !path.exists() {
        return Err(error::not_found("file is not found or expired :(\n"));
    }

    // Check password protection
    if paste_type == PasteType::ProtectedFile {
        if crate::password::has_password(&path) {
            let password = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(extract_password_from_auth)
                .ok_or_else(|| {
                    info!("PasteType::ProtectedFile: cannot extract password from headers");
                    error::not_found("file is not found or expired :(\n")
                })?;

            if !crate::password::verify_file_password(&path, &password)
                .map_err(|e| error::internal(format!("password verification: {e}")))?
            {
                // Same error as missing file (prevents enumeration)
                info!("PasteType::ProtectedFile: password verification failed");
                return Err(error::not_found("file is not found or expired :(\n"));
            }
        } else {
            error!("PasteType::ProtectedFile: no password metadata file");
            return Err(error::not_found("file is not found or expired :(\n"));
        }
    }

    match paste_type {
        PasteType::File | PasteType::RemoteFile | PasteType::Oneshot | PasteType::ProtectedFile => {
            let should_download = options.map(|v| v.download).unwrap_or(false);

            let mut mime_type = if should_download {
                mime::APPLICATION_OCTET_STREAM
            } else {
                mime_util::get_mime_type(&response_config.paste.mime_override, file.to_string())
                    .map_err(error::internal)?
            };
            if !should_download
                && is_text_like_mime(&mime_type, &response_config.paste.text_mime_overrides)
            {
                mime_type = TEXT_PLAIN_UTF_8;
            }
            let mut response = serve_named_file(&path, &mime_type, request).await?;
            if response_config.server.hardening.unwrap_or(false) {
                apply_security_headers(&mut response);
            }
            if paste_type.is_oneshot() {
                fs::rename(
                    &path,
                    path.with_file_name(format!(
                        "{}.{}",
                        file,
                        util::get_system_time()?.as_millis()
                    )),
                )?;
            }
            Ok(response)
        }
        PasteType::Url => found(&fs::read_to_string(&path)?),
        PasteType::OneshotUrl => {
            let resp = found(&fs::read_to_string(&path)?)?;
            fs::rename(
                &path,
                path.with_file_name(format!("{}.{}", file, util::get_system_time()?.as_millis())),
            )?;
            Ok(resp)
        }
    }
}

/// Streams a file with range and conditional request support and the given content type.
///
/// The file is opened before this returns, so it may be renamed while the body streams.
async fn serve_named_file(
    path: &PathBuf,
    mime_type: &Mime,
    request: Request,
) -> Result<Response, Error> {
    let mut response = ServeFile::new_with_mime(path, mime_type)
        .oneshot(request)
        .await
        .map_err(error::internal)?
        .map(Body::new);
    response.headers_mut().remove(CONTENT_DISPOSITION);
    Ok(response)
}

/// Adds security hardening headers to the response.
///
/// Sets `X-Content-Type-Options: nosniff` to prevent MIME sniffing and
/// `Content-Security-Policy: default-src 'none'; sandbox` to restrict
/// script execution and embedding.
fn apply_security_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
}

/// Returns `true` if the given MIME type represents text-like content that
/// should be rendered as `text/plain` instead of being downloaded.
///
/// A MIME type is considered text-like if any of the following hold:
/// - Its type is `text` (e.g. `text/html`, `text/x-shellscript`)
/// - It has a `+xml` or `+json` structured syntax suffix
/// - It matches one of the user-configured `overrides`
/// - It is a known text-like `application/` type (e.g. `application/json`, `application/xml`)
fn is_text_like_mime(mime_type: &mime::Mime, overrides: &[String]) -> bool {
    if mime_type.type_() == mime::TEXT {
        return true;
    }
    if let Some(suffix) = mime_type.suffix() {
        if matches!(suffix.as_str(), "xml" | "json") {
            return true;
        }
    }
    let essence = mime_type.essence_str();
    if overrides.iter().any(|v| v.eq_ignore_ascii_case(essence)) {
        return true;
    }
    matches!(
        essence,
        "application/javascript"
            | "application/ecmascript"
            | "application/json"
            | "application/x-www-form-urlencoded"
            | "application/x-javascript"
            | "application/xml"
    )
}

/// Remove a file from the upload directory.
async fn delete(
    _: Protected<DeleteToken>,
    State(state): State<AppState>,
    uri: Uri,
) -> Result<Response, Error> {
    let file = requested_file(&uri);
    let config = state.config()?;
    let mut path = PathBuf::new();
    for variant in PASTE_VARIANTS_LIST {
        path = util::glob_match_file(safe_path_join(
            variant.get_path(&config.server.upload_path)?,
            &file,
        )?)?;
        if path.exists() && path.is_file() {
            break;
        }
    }
    if !path.is_file() || !path.exists() {
        let protected_path = safe_path_join(
            PasteType::ProtectedFile.get_path(&config.server.upload_path)?,
            &file,
        )?;
        path = util::glob_match_file(protected_path)?;
    }
    if !path.is_file() || !path.exists() {
        return Err(error::not_found("file is not found or expired :(\n"));
    }

    // Delete content file first, then password (prevents unprotected window)
    match fs::remove_file(&path) {
        Ok(_) => {
            info!("deleted file: {:?}", file);
            crate::password::delete_password_file(&path).ok();
        }
        Err(e) => {
            error!("cannot delete file: {}", e);
            return Err(error::internal("cannot delete file"));
        }
    }
    Ok(plain_ok("file deleted\n"))
}

/// Expose version endpoint
fn version(state: &AppState) -> Result<Response, Error> {
    let config = state.config()?;
    if !config.server.expose_version.unwrap_or(false) {
        warn!("server is not configured to expose version endpoint");
        Err(error::not_found(""))?;
    }

    let version = env!("CARGO_PKG_VERSION");
    Ok(plain_ok(version.to_owned() + "\n"))
}

/// A field of a `multipart` request body.
struct Field {
    inner: multer::Field<'static>,
    content_disposition: Option<ContentDisposition>,
}

impl Field {
    /// Returns the `Content-Disposition` of the field if it is `form-data`.
    fn content_disposition(&self) -> Option<&ContentDisposition> {
        self.content_disposition.as_ref()
    }

    /// Reads the next chunk of the field.
    async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        self.inner.chunk().await.map_err(multipart_error)
    }
}

/// Reader of `multipart/*` request bodies.
///
/// Rejects requests and fields as the `multipart` RFCs require, so a malformed body is
/// answered with the same errors as before the port.
struct Multipart {
    inner: Option<(multer::Multipart<'static>, bool)>,
    error: Option<Error>,
}

impl Multipart {
    /// Prepares a reader for `body`, deferring a `Content-Type` error to the first field.
    fn new(headers: &HeaderMap, body: Body) -> Self {
        match Self::find_ct_and_boundary(headers) {
            Ok((content_type, boundary)) => Self {
                inner: Some((
                    multer::Multipart::new(body.into_data_stream(), boundary),
                    content_type.subtype() == mime::FORM_DATA,
                )),
                error: None,
            },
            Err(e) => Self {
                inner: None,
                error: Some(e),
            },
        }
    }

    /// Extracts the `Content-Type` and its boundary from the request headers.
    fn find_ct_and_boundary(headers: &HeaderMap) -> Result<(Mime, String), Error> {
        let content_type = headers
            .get(CONTENT_TYPE)
            .ok_or_else(|| error::bad_request("Could not find Content-Type header"))?
            .to_str()
            .ok()
            .and_then(|content_type| content_type.parse::<Mime>().ok())
            .ok_or_else(|| error::bad_request("Could not parse Content-Type header"))?;
        if content_type.type_() != mime::MULTIPART {
            return Err(error::unsupported_media_type(
                "Parsed Content-Type did not have 'multipart' top-level media type",
            ));
        }
        let boundary = content_type
            .get_param(mime::BOUNDARY)
            .map(|v| v.as_str().to_owned())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| error::bad_request("Multipart boundary is not found"))?;
        Ok((content_type, boundary))
    }

    /// Returns the next field of the body.
    async fn next(&mut self) -> Option<Result<Field, Error>> {
        if let Some(e) = self.error.take() {
            return Some(Err(e));
        }
        let (multipart, form_data) = self.inner.as_mut()?;
        let inner = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => return None,
            Err(e) => return Some(Err(multipart_error(e))),
        };
        let content_disposition = inner
            .headers()
            .get(CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(ContentDisposition::parse)
            .filter(ContentDisposition::is_form_data);
        if *form_data {
            // RFC 7578 §4.2: a "form-data" field must have a "form-data" disposition with a name.
            let Some(content_disposition) = &content_disposition else {
                return Some(Err(error::bad_request(
                    "Content-Disposition header was not found when parsing a \"form-data\" field",
                )));
            };
            if content_disposition.get_name().is_none() {
                return Some(Err(error::bad_request(
                    "Content-Disposition 'name' parameter was not found when parsing a \"form-data\" field",
                )));
            }
        }
        let nested = inner
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<Mime>().ok())
            .is_some_and(|v| v.type_() == mime::MULTIPART);
        if nested {
            return Some(Err(error::bad_request("Nested multipart is not supported")));
        }
        Some(Ok(Field {
            inner,
            content_disposition,
        }))
    }
}

/// Maps a `multipart` parsing error to its response.
fn multipart_error(error: multer::Error) -> Error {
    match error {
        multer::Error::IncompleteStream
        | multer::Error::IncompleteFieldData { .. }
        | multer::Error::IncompleteHeaders => error::bad_request("Multipart stream is incomplete"),
        _ => error::bad_request("Error during field parsing"),
    }
}

/// Handles file upload by processing `multipart/form-data`.
async fn upload(
    _: Protected<AuthToken>,
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, Error> {
    let (parts, body) = request.into_parts();
    let connection = ConnectionInfo::new(&parts);
    let host = connection
        .realip_remote_addr()
        .unwrap_or("unknown host")
        .to_string();
    let server_url = match state.config()?.server.url.clone() {
        Some(v) => v,
        None => {
            format!("{}://{}", connection.scheme, connection.host)
        }
    };
    let time = util::get_system_time()?;
    let mut expiry_date = header::parse_expiry_date(&parts.headers, time)?;
    if expiry_date.is_none() {
        expiry_date = state
            .config()?
            .paste
            .default_expiry
            .and_then(|v| time.checked_add(v).map(|t| t.as_millis()));
    }
    let mut payload = Multipart::new(&parts.headers, body);
    let mut urls: Vec<String> = Vec::new();
    while let Some(item) = payload.next().await {
        let header_filename = header::parse_header_filename(&parts.headers)?;
        let mut field = item?;
        let content = field
            .content_disposition()
            .ok_or_else(|| error::internal("payload must contain content disposition"))?
            .clone();
        if let Ok(paste_type) = PasteType::try_from(&content) {
            let mut bytes = Vec::<u8>::new();
            while let Some(chunk) = field.chunk().await? {
                bytes.extend_from_slice(&chunk);
            }
            if bytes.is_empty() {
                warn!("{} sent zero bytes", host);
                return Err(error::bad_request("invalid file size"));
            }
            if paste_type != PasteType::Oneshot
                && paste_type != PasteType::RemoteFile
                && paste_type != PasteType::OneshotUrl
                && paste_type != PasteType::ProtectedFile
                && expiry_date.is_none()
                && !state.config()?.paste.duplicate_files.unwrap_or(true)
            {
                let bytes_checksum = util::sha256_digest(&*bytes)?;
                let config = state.config()?;
                if let Some(file) = Directory::try_from(config.server.upload_path.as_path())?
                    .get_file(bytes_checksum)
                {
                    urls.push(format!(
                        "{}/{}\n",
                        server_url,
                        file.path
                            .file_name()
                            .map(|v| v.to_string_lossy())
                            .unwrap_or_default()
                    ));
                    continue;
                }
            }
            let mut paste = Paste {
                data: bytes.to_vec(),
                type_: paste_type,
            };
            let result = match paste.type_ {
                PasteType::File | PasteType::Oneshot | PasteType::ProtectedFile => {
                    let config = state.config()?;
                    paste.store_file(
                        content.get_file_name()?,
                        expiry_date,
                        header_filename,
                        &config,
                    )?
                }
                PasteType::RemoteFile => {
                    paste
                        .store_remote_file(
                            expiry_date,
                            header_filename,
                            &state.client,
                            &state.config,
                        )
                        .await?
                }
                PasteType::Url | PasteType::OneshotUrl => {
                    let config = state.config()?;
                    paste.store_url(expiry_date, header_filename, &config)?
                }
            };

            let mut file_name = result.filename;
            let password = result.password;

            info!(
                "{} ({}) is uploaded from {}",
                file_name,
                Byte::from_u128(paste.data.len() as u128)
                    .unwrap_or_default()
                    .get_appropriate_unit(UnitType::Decimal),
                host
            );
            let config = state.config()?;
            if let Some(handle_spaces_config) = config.server.handle_spaces {
                file_name = handle_spaces_config.process_filename(&file_name);
            }
            if let Some(pwd) = password {
                urls.push(format!("{server_url}/{file_name}\nPassword: {pwd}\n"));
            } else {
                urls.push(format!("{server_url}/{file_name}\n"));
            }
        } else {
            warn!("{} sent an invalid form field", host);
            return Err(error::bad_request("invalid form field"));
        }
    }
    Ok(plain_ok(urls.join("")))
}

/// File entry item for list endpoint.
#[derive(Serialize, Deserialize)]
pub struct ListItem {
    /// Uploaded file name.
    pub file_name: PathBuf,
    /// Size of the file in bytes.
    pub file_size: Option<u64>,
    /// Item type
    pub item_type: PasteType,
    /// ISO8601 formatted date-time of the moment the file was created (uploaded).
    pub creation_date_utc: Option<String>,
    /// ISO8601 formatted date-time string of the expiration timestamp if one exists for this file.
    pub expires_at_utc: Option<String>,
}

/// Returns the list of files.
fn list(state: &AppState) -> Result<Response, Error> {
    let config = state.config()?.clone();
    if !config.server.expose_list.unwrap_or(false) {
        warn!("server is not configured to expose list endpoint");
        Err(error::not_found(""))?;
    }

    let get_item_list = |item_type: PasteType| -> Result<Vec<ListItem>, Error> {
        let dir = item_type.get_path(&config.server.upload_path)?;

        //FIX: When running some tests (e.g. test_list) other folders than "root" does not exists
        if !fs::exists(&dir).unwrap_or(false) {
            return Ok(Vec::default());
        }
        Ok(fs::read_dir(dir.as_path())?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let metadata = match e.metadata() {
                        Ok(metadata) => {
                            if metadata.is_dir() {
                                return None;
                            }
                            metadata
                        }
                        Err(e) => {
                            error!("failed to read metadata: {e}");
                            return None;
                        }
                    };
                    let mut file_name = PathBuf::from(e.file_name());

                    let creation_date_utc = metadata.created().ok().map(|v| {
                        let millis = v
                            .duration_since(UNIX_EPOCH)
                            .expect("Time since UNIX epoch should be valid.")
                            .as_millis();
                        uts2ts::uts2ts(
                            i64::try_from(millis)
                                .expect("UNIX time should be smaller than i64::MAX")
                                / 1000,
                        )
                        .as_string()
                    });

                    let expires_at_utc = if let Some(expiration) = file_name
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .and_then(|v| v.parse::<i64>().ok())
                    {
                        file_name.set_extension("");
                        if util::get_system_time().ok()?
                            > Duration::from_millis(expiration.try_into().ok()?)
                        {
                            return None;
                        }
                        Some(uts2ts::uts2ts(expiration / 1000).as_string())
                    } else {
                        None
                    };
                    Some(ListItem {
                        file_name,
                        file_size: match item_type {
                            PasteType::File | PasteType::Oneshot => Some(metadata.len()),
                            _ => None,
                        },
                        item_type,
                        creation_date_utc,
                        expires_at_utc,
                    })
                })
            })
            .collect())
    };

    let entries: Vec<ListItem> = PASTE_VARIANTS_LIST
        .iter()
        .map(|variant| get_item_list(*variant))
        .collect::<Result<Vec<Vec<ListItem>>, Error>>()?
        .into_iter()
        .flatten()
        .collect();

    let body = serde_json::to_string(&entries).map_err(error::internal)?;
    Ok((
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        body,
    )
        .into_response())
}

/// Answers a request no route serves.
async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Builds the router of the server.
///
/// `HEAD /` and methods a path does not serve are answered with an empty `404`, and
/// `HEAD /version` and `HEAD /list` look up a file of that name, as before the port.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index).post(upload).head(not_found))
        .route("/{file}", get(get_file).head(serve).delete(delete))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::grant_tokens,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LandingPageConfig;
    use crate::middleware::ContentLengthLimiter;
    use crate::random::{RandomURLConfig, RandomURLType};
    use axum::http::header::AUTHORIZATION;
    use axum::http::{header, HeaderName, Method, StatusCode};
    use glob::glob;
    use http_body_util::BodyExt;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::str;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    /// Request builder for calling the router in tests.
    struct TestRequest {
        method: Method,
        uri: String,
        headers: HeaderMap,
        payload: Bytes,
    }

    impl TestRequest {
        fn default() -> Self {
            Self::with_uri("/")
        }

        fn with_uri(uri: &str) -> Self {
            Self {
                method: Method::GET,
                uri: uri.to_string(),
                headers: HeaderMap::new(),
                payload: Bytes::new(),
            }
        }

        fn get() -> Self {
            Self::default()
        }

        fn post() -> Self {
            Self {
                method: Method::POST,
                ..Self::default()
            }
        }

        fn delete() -> Self {
            Self {
                method: Method::DELETE,
                ..Self::default()
            }
        }

        fn uri(mut self, uri: &str) -> Self {
            self.uri = uri.to_string();
            self
        }

        fn insert_header<K, V>(mut self, (name, value): (K, V)) -> Self
        where
            K: TryInto<HeaderName>,
            V: TryInto<HeaderValue>,
        {
            let name = name.try_into().ok().expect("invalid header name");
            let value = value.try_into().ok().expect("invalid header value");
            self.headers.insert(name, value);
            self
        }

        fn set_payload(mut self, payload: impl Into<Bytes>) -> Self {
            self.payload = payload.into();
            self
        }

        #[allow(clippy::wrong_self_convention)]
        fn to_request(self) -> Request {
            let mut request = Request::new(Body::from(self.payload));
            *request.method_mut() = self.method;
            *request.uri_mut() = self.uri.parse().expect("invalid uri");
            *request.headers_mut() = self.headers;
            request
        }
    }

    fn init_service(config: Config) -> Router {
        router(AppState {
            config: Arc::new(RwLock::new(config)),
            client: reqwest::Client::new(),
        })
    }

    async fn call_service(app: &Router, request: Request) -> Response {
        app.clone()
            .oneshot(request)
            .await
            .expect("router is infallible")
    }

    async fn call_and_read_body_json<T: serde::de::DeserializeOwned>(
        app: &Router,
        request: Request,
    ) -> T {
        let response = call_service(app, request).await;
        let body = response
            .into_body()
            .collect()
            .await
            .expect("cannot read body")
            .to_bytes();
        serde_json::from_slice(&body).expect("invalid json body")
    }

    fn get_multipart_request(data: &str, name: &str, filename: &str) -> TestRequest {
        let multipart_data = format!(
            "\r\n\
             --multipart_bound\r\n\
             Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n\
             {}\r\n\
             --multipart_bound--\r\n",
            name,
            filename,
            data.len(),
            data,
        );
        TestRequest::post()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("multipart/mixed; boundary=\"multipart_bound\""),
            ))
            .insert_header((
                header::CONTENT_LENGTH,
                header::HeaderValue::from_str(&data.len().to_string())
                    .expect("cannot create header value"),
            ))
            .set_payload(multipart_data)
    }

    async fn assert_body(body: Body, expected: &str) -> Result<(), Error> {
        let body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();
        assert_eq!(body_bytes.len(), expected.len());
        let body_text = str::from_utf8(&body_bytes).map_err(error::internal)?;
        assert_eq!(expected, body_text);
        Ok(())
    }

    #[test]
    fn test_is_text_like_mime_defaults() {
        let overrides = Vec::<String>::new();
        assert!(is_text_like_mime(
            &mime::Mime::from_str("text/plain").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/atom+xml").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/problem+json").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("image/svg+xml").expect("invalid mime"),
            &overrides
        ));
        assert!(!is_text_like_mime(
            &mime::Mime::from_str("application/octet-stream").expect("invalid mime"),
            &overrides
        ));
    }

    #[test]
    fn test_is_text_like_mime_overrides() {
        let overrides = vec![
            String::from("application/toml"),
            String::from("application/x-yaml"),
        ];
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/toml").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/x-yaml").expect("invalid mime"),
            &overrides
        ));
        assert!(!is_text_like_mime(
            &mime::Mime::from_str("application/pdf").expect("invalid mime"),
            &overrides
        ));
    }

    #[tokio::test]
    async fn test_index() {
        let config = Config::default();
        let app = init_service(config);
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
    }

    #[tokio::test]
    async fn test_index_with_landing_page() -> Result<(), Error> {
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = init_service(config);
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_index_with_landing_page_file() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut file = File::create(filename)?;
        file.write_all("landing page from file".as_bytes())?;
        let app = init_service(config);
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page from file").await?;
        fs::remove_file(filename)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_index_with_landing_page_file_not_found() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = init_service(config);
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
        Ok(())
    }

    #[tokio::test]
    async fn test_version_without_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());
        let app = init_service(config);

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_version_without_config() -> Result<(), Error> {
        let app = init_service(Config::default());

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_version() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_version = Some(true);
        let app = init_service(config);

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &(env!("CARGO_PKG_VERSION").to_owned() + "\n"),
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_list() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = init_service(config);

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename).to_request(),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = call_and_read_body_json(&app, request).await;

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.first().expect("json object").file_name,
            PathBuf::from(filename)
        );

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_list_item_type() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        config.server.upload_path = PathBuf::from(test_upload_dir);

        for variant in PASTE_VARIANTS_LIST {
            fs::create_dir_all(
                variant
                    .get_path(&config.server.upload_path)
                    .expect("Bad upload path"),
            )?;
        }

        let app = init_service(config);

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename).to_request(),
        )
        .await;
        let filename_oneshot = "oneshot.txt";
        call_service(
            &app,
            get_multipart_request(&timestamp, "oneshot", filename_oneshot).to_request(),
        )
        .await;
        call_service(
            &app,
            get_multipart_request(env!("CARGO_PKG_HOMEPAGE"), "url", "").to_request(),
        )
        .await;
        let filename_oneshot_url = "oneshot_url";
        call_service(
            &app,
            get_multipart_request(
                env!("CARGO_PKG_HOMEPAGE"),
                filename_oneshot_url,
                filename_oneshot_url,
            )
            .to_request(),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = call_and_read_body_json(&app, request).await;

        assert_eq!(result.len(), 4);

        // Items returned from `/list` endpoint should be returned in this order:
        // 1. PasteType::File
        // 2. PasteType::Oneshot
        // 3. PasteType::Url
        // 4. PasteType::OneshotUrl
        // NOTE: The test won't pass if order in `PASTE_VARIANTS_LIST` changes

        assert_eq!(result[0].file_name, PathBuf::from(filename));
        assert_eq!(result[0].item_type, PasteType::File);

        assert_eq!(result[1].file_name, PathBuf::from(filename_oneshot));
        assert_eq!(result[1].item_type, PasteType::Oneshot);

        assert_eq!(result[2].file_name, PathBuf::from("url"));
        assert_eq!(result[2].item_type, PasteType::Url);

        assert_eq!(result[3].file_name, PathBuf::from(filename_oneshot_url));
        assert_eq!(result[3].item_type, PasteType::OneshotUrl);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_list_expired() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = init_service(config);

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("50ms"),
                ))
                .to_request(),
        )
        .await;

        thread::sleep(Duration::from_millis(500));

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = call_and_read_body_json(&app, request).await;

        assert!(result.is_empty());

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_list_excludes_password_files() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload_protected_list";
        // Clean up from any previous test runs
        let _ = fs::remove_dir_all(test_upload_dir);
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        // Create protected subdirectory
        fs::create_dir(PathBuf::from(test_upload_dir).join("protected"))?;

        let app = init_service(config);

        let filename = "secret.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();

        // Upload a protected file (creates both secret.txt and secret.txt.password in protected/ subdir)
        call_service(
            &app,
            get_multipart_request(&timestamp, "protected", filename).to_request(),
        )
        .await;

        // Verify both files exist in protected/ subdirectory
        let main_file = PathBuf::from(test_upload_dir)
            .join("protected")
            .join(filename);
        let password_file = PathBuf::from(test_upload_dir)
            .join("protected")
            .join(format!("{filename}.password"));
        assert!(main_file.exists());
        assert!(password_file.exists());

        // Call /list endpoint (reads root directory only)
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = call_and_read_body_json(&app, request).await;

        // Should return 0 files (protected files are in subdirectory, not shown in root listing)
        assert_eq!(result.len(), 0);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());

        let app = init_service(config);

        let response = call_service(&app, get_multipart_request("", "", "").to_request()).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_payload_limit() -> Result<(), Error> {
        let app =
            init_service(Config::default()).layer(ContentLengthLimiter::new(Byte::from_u64(1)));

        let response = call_service(
            &app,
            get_multipart_request("test", "file", "test").to_request(),
        )
        .await;
        assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, response.status());
        assert_body(response.into_body(), "upload limit exceeded").await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.delete_tokens = Some(["test".to_string()].into());
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;

        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "file deleted\n").await?;

        let path = PathBuf::from(file_name);
        assert!(!path.exists());

        let password_path = PathBuf::from(format!("{file_name}.password"));
        assert!(!password_path.exists(), "password file should be deleted");

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_protected_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.delete_tokens = Some(["test".to_string()].into());
        config.server.upload_path = env::current_dir()?;

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("cannot get protected file path");
        fs::create_dir_all(&protected_upload_path)?;

        let app = init_service(config);

        let file_name = "test_protected_delete.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        call_service(
            &app,
            get_multipart_request(&timestamp, "protected", file_name).to_request(),
        )
        .await;

        let path = protected_upload_path.join(file_name);
        let password_path = protected_upload_path.join(format!("{file_name}.password"));
        assert!(path.exists());
        assert!(password_path.exists());

        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "file deleted\n").await?;

        assert!(!path.exists());
        assert!(
            !password_path.exists(),
            "password file should be deleted with the content file"
        );

        fs::remove_dir(protected_upload_path)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_file_without_token_in_config() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(file_name)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_file_override_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(header_filename)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_same_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::CONFLICT, response.status());
        assert_body(response.into_body(), "file already exists\n").await?;

        fs::remove_file(header_filename)?;

        Ok(())
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_upload_duplicate_file() -> Result<(), Error> {
        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(&test_upload_dir);
        config.paste.duplicate_files = Some(false);
        config.paste.random_url = Some(RandomURLConfig {
            enabled: Some(true),
            type_: RandomURLType::Alphanumeric,
            ..Default::default()
        });

        let app = init_service(config);

        let response = call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let first_body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();

        let response = call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let second_body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();

        assert_eq!(first_body_bytes, second_body_bytes);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_expiring_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config);

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("20ms"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        thread::sleep(Duration::from_millis(40));

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(&format!("{file_name}.[0-9]*"))
            .map_err(error::internal)?
            .next()
        {
            fs::remove_file(glob_path.map_err(error::internal)?)?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_remote_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;
        config.server.max_content_length = Byte::from_u128(30000).unwrap_or_default();

        let app = init_service(config);

        let file_name =
            "rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png";
        let response = call_service(
            &app,
            get_multipart_request(
                "https://raw.githubusercontent.com/orhun/rustypaste/refs/heads/master/img/rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png",
                "remote",
                file_name,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());

        let body = response.into_body();
        let body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();
        assert_eq!(
            "3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f",
            util::sha256_digest(&*body_bytes)?
        );

        fs::remove_file(file_name)?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_remote_file_override_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;
        config.server.max_content_length = Byte::from_u128(30000).unwrap_or_default();

        let app = init_service(config);

        let file_name = "fn_from_header.txt";
        let response = call_service(
            &app,
            get_multipart_request(
                "https://raw.githubusercontent.com/orhun/rustypaste/refs/heads/master/img/rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png",
                "remote",
                file_name,
            )
            .insert_header((
                header::HeaderName::from_static("filename"),
                header::HeaderValue::from_static(file_name),
            ))
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());

        let body = response.into_body();
        let body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();
        assert_eq!(
            "3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f",
            util::sha256_digest(&*body_bytes)?
        );

        fs::remove_file(file_name)?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config.clone());

        let url_upload_path = PasteType::Url
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = call_service(
            &app,
            get_multipart_request(env!("CARGO_PKG_HOMEPAGE"), "url", "").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "http://localhost:8080/url\n").await?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        fs::remove_file(url_upload_path.join("url"))?;
        fs::remove_dir(url_upload_path)?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_oneshot() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = init_service(config.clone());

        let oneshot_upload_path = PasteType::Oneshot
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&oneshot_upload_path)?;

        let file_name = "oneshot.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = call_service(
            &app,
            get_multipart_request(&timestamp, "oneshot", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(
            &oneshot_upload_path
                .join(format!("{file_name}.[0-9]*"))
                .to_string_lossy(),
        )
        .map_err(error::internal)?
        .next()
        {
            fs::remove_file(glob_path.map_err(error::internal)?)?;
        }
        fs::remove_dir(oneshot_upload_path)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_oneshot_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let oneshot_url_suffix = "oneshot_url";

        let app = init_service(config.clone());

        let url_upload_path = PasteType::OneshotUrl
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = call_service(
            &app,
            get_multipart_request(
                env!("CARGO_PKG_HOMEPAGE"),
                oneshot_url_suffix,
                oneshot_url_suffix,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{oneshot_url_suffix}\n"),
        )
        .await?;

        // Make the oneshot_url request, ensure it is found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        // Make the same request again, and ensure that the oneshot_url is not found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Cleanup
        fs::remove_dir_all(url_upload_path)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_protected_file() -> Result<(), Error> {
        let test_upload_dir = "test_upload_protected";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = init_service(config.clone());

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&protected_upload_path)?;

        let file_name = "protected.txt";
        let file_content = "secret content";

        // Upload protected file
        let response = call_service(
            &app,
            get_multipart_request(file_content, "protected", file_name).to_request(),
        )
        .await;

        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let body_bytes = body.collect().await.map_err(error::internal)?.to_bytes();
        let body_text = str::from_utf8(&body_bytes).map_err(error::internal)?;

        // Extract URL and password from response
        let lines: Vec<&str> = body_text.lines().collect();
        assert_eq!(2, lines.len(), "Expected URL and password in response");
        assert!(
            lines[0].contains(file_name),
            "First line should contain URL"
        );
        assert!(
            lines[1].starts_with("Password: "),
            "Second line should contain password"
        );

        let password = lines[1]
            .strip_prefix("Password: ")
            .expect("Failed to extract password")
            .to_string();

        // Access without authorization header -> 404
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with wrong password (Bearer) -> 404
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, "Bearer wrongpassword"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with wrong password (Basic Auth) -> 404
        let wrong_basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"user:wrongpassword"
            )
        );
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, wrong_basic))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with correct password (Bearer) -> 200
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, format!("Bearer {password}")))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), file_content).await?;

        // Access with correct password (Basic Auth) -> 200
        let correct_basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("user:{password}").as_bytes()
            )
        );
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, correct_basic))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), file_content).await?;

        // Cleanup
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_protected_file_enumeration_prevention() -> Result<(), Error> {
        let test_upload_dir = "test_upload_enum";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = init_service(config.clone());

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&protected_upload_path)?;

        // Test that both missing files and protected files return same error code
        // This prevents attackers from enumerating files

        // Request non-existent file -> 404
        let serve_request = TestRequest::get().uri("/nonexistent.txt").to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Upload protected file
        let file_name = "protected_enum.txt";
        let response = call_service(
            &app,
            get_multipart_request("content", "protected", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());

        // Request protected file without auth -> 404 (same as non-existent)
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Request protected file with wrong password -> 404 (same as non-existent)
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, "Bearer wrongpassword"))
            .to_request();
        let response = call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Cleanup
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }
}
