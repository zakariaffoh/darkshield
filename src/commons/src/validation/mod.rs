use regex::Regex;
pub struct EmailValidator;

const EMAIL_PATTERN: &str = r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*";
impl EmailValidator {
    pub fn validate(email: &str) -> Result<bool, String> {
        let response = Regex::new(EMAIL_PATTERN).unwrap().is_match(email);
        if response {
            return Ok(true);
        } else {
            return Err("Invalid email".to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EmailValidator;

    #[test]
    fn validate_email() {
        assert_eq!(true, EmailValidator::validate("zed@nathos.tg").unwrap());
        assert_eq!(
            "Invalid email",
            EmailValidator::validate("zednathos.tg")
                .err()
                .unwrap()
                .to_owned()
        );
    }
}
