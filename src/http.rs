use lambda_http::{Body, Error, Response};
use serde::Serialize;

pub fn json<T: Serialize>(status: u16, body: &T) -> Result<Response<Body>, Error> {
    let body = serde_json::to_vec(body)?;

    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "application/json; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Body::Binary(body))
        .map_err(Into::into)
}

pub fn json_error(status: u16, code: &str, message: &str) -> Result<Response<Body>, Error> {
    json(
        status,
        &serde_json::json!({
            "code": code,
            "error": message,
        }),
    )
}
