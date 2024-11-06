use serde::Serialize;

#[derive(Serialize)]
pub struct Output {
    pub status: String,
    pub secret: Option<String>,
    pub detail: String,
    pub usage: Option<String>,
}