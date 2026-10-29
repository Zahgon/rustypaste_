use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use hotwatch::notify::event::ModifyKind;
use hotwatch::{Event, EventKind, Hotwatch};
use rustypaste::config::{Config, ServerConfig};
use rustypaste::middleware::ContentLengthLimiter;
use rustypaste::paste::PasteType;
use rustypaste::server::{self, AppState};
use rustypaste::util;
use rustypaste::CONFIG_ENV;
use std::env;
use std::fs;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter,
};

// Use macros from tracing crate.
#[macro_use]
extern crate tracing;

/// Sets up the application.
///
/// * loads the configuration
/// * initializes the logger
/// * creates the necessary directories
/// * spawns the threads
fn setup(config_folder: &Path) -> IoResult<(Arc<RwLock<Config>>, ServerConfig, Hotwatch)> {
    // Load the .env file.
    dotenvy::dotenv().ok();

    // Initialize logger.
    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse configuration.
    let config_path = match env::var(CONFIG_ENV).ok() {
        Some(path) => {
            unsafe {
                env::remove_var(CONFIG_ENV);
            }
            PathBuf::from(path)
        }
        None => config_folder.join("config.toml"),
    };
    if !config_path.exists() {
        error!(
            "{} is not found, please provide a configuration file.",
            config_path.display()
        );
        std::process::exit(1);
    }
    let config = Config::parse(&config_path).expect("failed to parse config");
    trace!("{:#?}", config);
    config.warn_deprecation();
    let server_config = config.server.clone();
    let paste_config = RwLock::new(config.paste.clone());
    let (config_sender, config_receiver) = mpsc::channel::<Config>();

    // Create necessary directories.
    fs::create_dir_all(&server_config.upload_path)?;
    for paste_type in &[
        PasteType::Url,
        PasteType::Oneshot,
        PasteType::OneshotUrl,
        PasteType::ProtectedFile,
    ] {
        fs::create_dir_all(paste_type.get_path(&server_config.upload_path)?)?;
    }

    // Set up a watcher for the configuration file changes.
    let mut hotwatch = Hotwatch::new_with_custom_delay(
        config
            .settings
            .as_ref()
            .map(|v| v.refresh_rate)
            .unwrap_or_else(|| Duration::from_secs(1)),
    )
    .expect("failed to initialize configuration file watcher");

    // Hot-reload the configuration file.
    let config = Arc::new(RwLock::new(config));
    let cloned_config = Arc::clone(&config);
    let config_watcher = move |event: Event| {
        if let (EventKind::Modify(ModifyKind::Data(_)), Some(path)) =
            (event.kind, event.paths.first())
        {
            match Config::parse(path) {
                Ok(config) => match cloned_config.write() {
                    Ok(mut cloned_config) => {
                        *cloned_config = config.clone();
                        info!("Configuration has been updated.");
                        if let Err(e) = config_sender.send(config) {
                            error!("Failed to send config for the cleanup routine: {}", e)
                        }
                        cloned_config.warn_deprecation();
                    }
                    Err(e) => {
                        error!("Failed to acquire config: {}", e);
                    }
                },
                Err(e) => {
                    error!("Failed to update config: {}", e);
                }
            }
        }
    };
    hotwatch
        .watch(&config_path, config_watcher)
        .unwrap_or_else(|_| panic!("failed to watch {config_path:?}"));

    // Create a thread for cleaning up expired files.
    let upload_path = server_config.upload_path.clone();
    thread::spawn(move || loop {
        let mut enabled = false;
        if let Some(ref cleanup_config) = paste_config
            .read()
            .ok()
            .and_then(|v| v.delete_expired_files.clone())
        {
            if cleanup_config.enabled {
                debug!("Running cleanup...");
                // Clean up expired files
                for file in util::get_expired_files(&upload_path) {
                    // Delete content file first, then password (prevents unprotected window)
                    match fs::remove_file(&file) {
                        Ok(()) => {
                            info!("Removed expired file: {:?}", file);
                            rustypaste::password::delete_password_file(&file).ok();
                        }
                        Err(e) => error!("Cannot remove expired file: {}", e),
                    }
                }

                // Clean orphaned password files
                for password_file in util::get_orphaned_password_files(&upload_path) {
                    match fs::remove_file(&password_file) {
                        Ok(()) => info!("Removed orphaned password: {:?}", password_file),
                        Err(e) => error!("Cannot remove orphaned password: {}", e),
                    }
                }

                thread::sleep(cleanup_config.interval);
            }
            enabled = cleanup_config.enabled;
        }
        if let Some(new_config) = if enabled {
            config_receiver.try_recv().ok()
        } else {
            config_receiver.recv().ok()
        } {
            match paste_config.write() {
                Ok(mut paste_config) => {
                    *paste_config = new_config.paste;
                }
                Err(e) => {
                    error!("Failed to update config for the cleanup routine: {}", e);
                }
            }
        }
    });

    Ok((config, server_config, hotwatch))
}

/// Logs every request with its status and duration.
async fn log_request(request: Request, next: Next) -> Response {
    let line = format!(
        "\"{} {} {:?}\"",
        request.method(),
        request.uri(),
        request.version()
    );
    let start = Instant::now();
    let response = next.run(request).await;
    info!(
        "{} {} {:.6}",
        line,
        response.status().as_u16(),
        start.elapsed().as_secs_f64()
    );
    response
}

fn main() -> IoResult<()> {
    // Set up the application.
    let (config, server_config, _hotwatch) = setup(&PathBuf::new())?;

    // Set worker count for the server.
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    if let Some(workers) = server_config.workers {
        runtime.worker_threads(workers);
    }
    runtime
        .enable_all()
        .build()?
        .block_on(serve(config, server_config))
}

/// Runs the HTTP server.
async fn serve(config: Arc<RwLock<Config>>, server_config: ServerConfig) -> IoResult<()> {
    // Create an HTTP client for remote uploads.
    let client = reqwest::Client::builder()
        .timeout(
            server_config
                .timeout
                .unwrap_or_else(|| Duration::from_secs(30)),
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(std::io::Error::other)?;
    let app = server::router(AppState { config, client })
        .layer(ContentLengthLimiter::new(server_config.max_content_length))
        .layer(middleware::from_fn(log_request));

    // Create an HTTP server.
    let listener = tokio::net::TcpListener::bind(&server_config.address).await?;

    // Run the server.
    info!("Server is running at {}", server_config.address);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
