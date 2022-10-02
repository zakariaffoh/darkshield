pub struct ActionToken{
    pub user_id: String,
    pub action_id: String,
    pub expiration_in_seconds: i64,
    pub action_verification_nonce: Option<String>,
    pub notes: Option<HashMap<String, String>>,
}

impl ActionToken{
    pub new(
        user_id: &str,
        action_id: &str,
        expiration_in_seconds: i64,
        action_verification_nonce: &str,
        notes: Option<HashMap<String, String>>,
    ) -> Self{
        Self{
            user_id.to_owned(),
            action_id.to_owned(),
            expiration_in_seconds,
            action_verification_nonce.to_owned(),
            notes,
        }
    }

    pub fn serialize(&self) -> String{
        let token = format!("{}.{}{}{}", self.user_id, self.action_id, self.expiration_in_seconds, self.action_verification_nonce);
        todo!()
        /*
        return str(base64.urlsafe_b64encode(token.encode("utf_8")))
        */
    }

    pub fn deserialize(&mut self, action_token: str){
        todo!()
    }

    pub fn set_note(&mut self, name: &str, value:&str) -> Option<String>{
        match &self.notes{
            Some(notes){
                let existing_note = notes.get(&name).clone();
                notes.insert(name.to_owned(), value.to_owned());
                return existing_note;
            }
            None {
                let mut notes = HashMap::new();
                notes.insert(name.to_owned(), value.to_owned());
                self.notes = Some(notes);
                None 
            }
        }
    }

    pub remove_note(&mut self, name: &str) -> Option<String>{
        match &self.notes{
            Some(notes){
                let existing_note = notes.get(&name).clone();
                notes.remove(&name);
                return existing_note;
            }
            None => None
        }
    }
}