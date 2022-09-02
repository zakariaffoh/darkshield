use actix_web::{body::BoxBody, http::header::ContentType, HttpResponse, Responder};
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct ErrorMessage {
    error_code: String,
    message: String,
}

#[derive(Serialize, Debug)]
pub struct ApiError {
    error: ErrorMessage,
    status_code: u16,
}

#[allow(unused)]
pub enum ApiResult<T = ()> {
    Data(T),
    Error(ApiError),
    Empty,
}

#[allow(dead_code)]
impl<T> ApiResult<T> {
    pub fn from_data(data: T) -> Self {
        ApiResult::Data(data)
    }

    pub fn error(error: ApiError) -> Self {
        ApiResult::Error(error)
    }

    pub fn from_error(status_code: u16, error_code: &str, message: &str) -> Self {
        ApiResult::Error(ApiError {
            error: ErrorMessage {
                error_code: error_code.to_owned(),
                message: message.to_owned(),
            },
            status_code: status_code,
        })
    }
    pub fn no_content() -> Self {
        ApiResult::Empty
    }
}

impl<T> Responder for ApiResult<T>
where
    T: Serialize,
{
    type Body = BoxBody;

    fn respond_to(self, _: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        match &self {
            ApiResult::Data(data) => HttpResponse::Ok()
                .content_type(ContentType::json())
                .body(serde_json::to_string(data).unwrap()),
            ApiResult::Error(error) => HttpResponse::Ok()
                .content_type(ContentType::json())
                .body(serde_json::to_string(error).unwrap()),
            ApiResult::Empty => HttpResponse::NoContent()
                .content_type(ContentType::json())
                .body(()),
        }
    }
}
