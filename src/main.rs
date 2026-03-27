use lambda_http::http::Method;
use lambda_http::{run, service_fn, Body, Error, Request, Response};

mod config;
mod error;
mod exchange;
mod github;
mod http;
mod jwks;
mod replay;
mod types;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = config::load().await?;

    run(service_fn(move |request: Request| {
        let config = config.clone();
        async move { router(config, request).await }
    }))
    .await
}

async fn router(config: config::Config, request: Request) -> Result<Response<Body>, Error> {
    match (request.method().clone(), request.uri().path()) {
        (Method::GET, "/health") => http::json(
            200,
            &serde_json::json!({
                "ok": true,
                "service": "ost-simple-sts",
            }),
        ),
        (Method::POST, "/exchange") => exchange::handle(config, request).await,
        _ => http::json_error(404, "not_found", "not found"),
    }
}
