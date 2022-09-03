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
    NotFound,
    NoContent,
}

#[allow(dead_code)]
impl<T> ApiResult<T> {
    pub fn from_data(data: T) -> Self {
        ApiResult::Data(data)
    }

    pub fn from_option(data: Option<T>) -> Self {
        match data {
            Some(d) => ApiResult::Data(d),
            None => ApiResult::NotFound,
        }
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
        ApiResult::<T>::NoContent
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
            ApiResult::Error(error) => match error.status_code {
                400 => HttpResponse::BadRequest()
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(error).unwrap()),
                403 => HttpResponse::Unauthorized()
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(error).unwrap()),
                404 => HttpResponse::NotFound()
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(error).unwrap()),
                409 => HttpResponse::Conflict()
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(error).unwrap()),
                _ => HttpResponse::InternalServerError()
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(error).unwrap()),
            },
            ApiResult::NotFound => HttpResponse::NotFound()
                .content_type(ContentType::json())
                .body(()),
            ApiResult::NoContent => HttpResponse::NoContent()
                .content_type(ContentType::json())
                .body(()),
        }
    }
}
