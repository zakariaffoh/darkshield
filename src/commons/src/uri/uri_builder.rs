use actix_web::http::Uri;

pub struct UriBuilder;

impl UriBuilder {
    pub fn from_uri(_uri: Uri) -> Self {
        todo!()
    }

    pub fn path(&self, _parth1: &str) -> Self {
        todo!()
    }

    pub fn paths(&self, _parth1: &str, _parth2: &str, _parth3: &str) -> Self {
        todo!()
    }

    pub fn build(&self) -> String {
        todo!()
    }

    pub fn clone(&self) -> Self {
        todo!()
    }
}
