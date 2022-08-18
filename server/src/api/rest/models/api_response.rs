use actix_web::{
    body::BoxBody,
    http::{header::ContentType, StatusCode},
    HttpResponse, Responder,
};
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
pub struct ApiResponse<T> {
    data: Option<T>,
    error: Option<ApiError>,
}

#[allow(dead_code)]
impl<T> ApiResponse<T> {
    pub fn from_data(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: ApiError) -> Self {
        Self {
            data: None,
            error: Some(error),
        }
    }
}

impl<T> Responder for ApiResponse<T>
where
    T: Serialize,
{
    type Body = BoxBody;
    fn respond_to(self, _: &actix_web::HttpRequest) -> actix_web::HttpResponse<Self::Body> {
        match (self.data, self.error) {
            (Some(ref data), _) => HttpResponse::Ok()
                .content_type(ContentType::json())
                .body(serde_json::to_string(data).unwrap()),

            (_, Some(ref error)) => {
                HttpResponse::build(StatusCode::from_u16(error.status_code).unwrap())
                    .content_type(ContentType::json())
                    .body(serde_json::to_string(&error.error).unwrap())
            }
            (_, _) => HttpResponse::InternalServerError()
                .content_type(ContentType::json())
                .body("server internal error"),
        }
    }
}
