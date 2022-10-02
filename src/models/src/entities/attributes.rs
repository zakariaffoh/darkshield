use std::collections::HashMap;

use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum AttributeValue {
    Int(i64),
    Str(String),
    Bool(bool),
    ListStr(Vec<String>),
}

pub type AttributesMap = HashMap<String, AttributeValue>;

pub struct AttributeHelper;

impl AttributeHelper {
    pub fn string_value(value: &AttributeValue) -> Result<String, String> {
        if let AttributeValue::Str(val) = value {
            return Ok(val.to_string());
        } else {
            return Err("invalid string".to_owned());
        }
    }

    pub fn int_value(value: &AttributeValue) -> Result<i64, String> {
        if let AttributeValue::Int(val) = value {
            return Ok(*val);
        } else {
            return Err("invalid string".to_owned());
        }
    }

    pub fn bool_value(value: &AttributeValue) -> Result<bool, String> {
        if let AttributeValue::Bool(val) = value {
            return Ok(*val);
        } else {
            return Err("invalid bool".to_owned());
        }
    }

    pub fn decimal_value(value: &AttributeValue) -> Result<f64, String> {
        match value {
            AttributeValue::Int(val) => Ok(*val as f64),
            AttributeValue::Str(val) => {
                let result = val.parse::<f64>();
                match result {
                    Ok(r) => return Ok(r),
                    Err(_) => return Err("invalid decinal".to_owned()),
                }
            }
            _ => return Err("invalid decinal".to_owned()),
        }
    }

    pub fn is_valid_attribute(value: &AttributeValue) -> bool {
        match value {
            AttributeValue::Bool(_) => return true,
            AttributeValue::Int(_) => return true,
            AttributeValue::Str(_) => return true,
            AttributeValue::ListStr(_) => return true,
            _ => return false,
        }
    }

}
pub struct AttributeMapHelper;

impl AttributeMapHelper{
    pub fn bool_value(
        attributes: &AttributesMap,
        attr_name: &str,
    ) -> Option<bool>{
        if attributes.is_none(){
            return None
        }

        let attribute = attributes.get(attr_name);
        if let Some(attr)  = attribute {
            match AttributeHelper::bool_value(&attr){
                Ok(attr_value) => return Ok(attr_value),
                Err(_) => retun None
            }
        }
        return None
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::attributes::AttributeValue;

    #[test]
    fn serialize_bool_attribute() {
        let result = serde_json::from_str::<AttributeValue>(
            serde_json::to_string(&AttributeValue::Bool(true))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(result, AttributeValue::Bool(true));
    }

    #[test]
    fn serialize_string_attribute() {
        let result = serde_json::from_str::<AttributeValue>(
            serde_json::to_string(&AttributeValue::Str("My test".to_owned()))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(result, AttributeValue::Str("My test".to_owned()));
    }

    #[test]
    fn serialize_int_attribute() {
        let result = serde_json::from_str::<AttributeValue>(
            serde_json::to_string(&AttributeValue::Int(456))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(result, AttributeValue::Int(456));
    }

    #[test]
    fn serialize_list_str_attribute() {
        let result = serde_json::from_str::<AttributeValue>(
            serde_json::to_string(&AttributeValue::ListStr(vec!["Test1".to_owned()]))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(result, AttributeValue::ListStr(vec!["Test1".to_owned()]));
    }
}
