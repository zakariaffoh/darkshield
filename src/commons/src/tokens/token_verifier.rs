use super::jwt::Jwt;

pub trait TokenVerifier {
    fn verify(&self, token: Box<&dyn Jwt>) -> bool;
}
