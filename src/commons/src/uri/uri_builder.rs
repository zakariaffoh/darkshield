use actix_web::http::Uri;

pub struct UriBuilder;

impl UriBuilder {
    pub fn from_uri(_uri: Uri) -> Self {
        todo!()
    }

    pub fn path(&self, parth1: &str) -> Self {
        todo!()
    }

    pub fn paths(&self, parth1: &str, parth2: &str, parth3: &str) -> Self {
        todo!()
    }

    pub fn build(&self) -> String {
        todo!()
    }

    pub fn clone(&self) -> Self {
        todo!()
    }
}
