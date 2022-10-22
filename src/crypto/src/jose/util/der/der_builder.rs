#![allow(unused)]

use crate::jose::util::oid::ObjectIdentifier;

use super::der_type::DerType;

pub struct DerBuilder {
    stack: Vec<Vec<u8>>,
}

impl DerBuilder {
    pub fn new() -> Self {
        Self {
            stack: vec![Vec::new()],
        }
    }

    pub fn begin(&mut self, der_type: DerType) {
        let current = self.stack.last_mut().unwrap();

        let class_no = der_type.der_class().class_no();
        let tag_no = der_type.tag_no();

        let ident = (class_no & 0b11) << 6 | 0b1 << 5;
        if tag_no < 30 {
            current.push(ident | (tag_no as u8 & 0b11111));
        } else {
            current.push(ident | 0b11111);

            let mut n = tag_no;
            while n > 0b01111111 {
                current.push((n as u8 & 0b01111111) | 0b10000000);
                n >>= 7;
            }
            current.push(n as u8);
        }

        self.stack.push(Vec::new());
    }

    pub fn append_integer_from_u8(&mut self, value: u8) {
        self.append(DerType::Integer, None, &[value]);
    }

    pub fn append_integer_from_u64(&mut self, value: u64) {
        let mut vec = Vec::new();
        let mut rest = value;
        while rest > 0 {
            vec.push((rest & 0xFF) as u8);
            rest >>= 8;
        }
        self.append(DerType::Integer, None, &vec);
    }

    pub fn append_integer_from_be_slice(&mut self, value: &[u8], sign: bool) {
        let prefix = if sign && value.len() > 0 && value[0] & 0b10000000 != 0 {
            Some(0)
        } else {
            None
        };

        self.append(DerType::Integer, prefix, value);
    }

    pub fn append_null(&mut self) {
        self.append(DerType::Null, None, &[]);
    }

    pub fn append_object_identifier(&mut self, oid: &ObjectIdentifier) {
        let mut vec = Vec::<u8>::new();

        let mut iter = oid.into_iter();
        if let Some(level1) = iter.next() {
            if let Some(level2) = iter.next() {
                vec.push((level1 * 40 + level2) as u8);
            } else {
                vec.push((level1 * 40) as u8);
            }
        }

        for n in iter {
            let n = *n;
            let mut start = false;
            let mut shift = 9;
            loop {
                let part = ((n >> 7 * shift) & 0x7F) as u8;
                if shift == 0 {
                    vec.push(part);
                    break;
                } else if start || part != 0 {
                    vec.push(part | 0x80);
                    start = true;
                }
                shift -= 1;
            }
        }

        self.append(DerType::ObjectIdentifier, None, &vec);
    }

    pub fn append_octed_string_from_bytes(&mut self, contents: &[u8]) {
        self.append(DerType::OctetString, None, contents);
    }

    pub fn append_bit_string_from_bytes(&mut self, contents: &[u8], trailing_len: u8) {
        if trailing_len >= 8 {
            unreachable!();
        }

        self.append(DerType::BitString, Some(trailing_len), contents);
    }

    pub fn append(&mut self, der_type: DerType, prefix: Option<u8>, contents: &[u8]) {
        let current = self.stack.last_mut().unwrap();

        let class_no = der_type.der_class().class_no();
        let tag_no = der_type.tag_no();

        let ident = (class_no & 0b11) << 6;
        if tag_no < 30 {
            current.push(ident | (tag_no as u8 & 0b11111));
        } else {
            current.push(ident | 0b11111);

            let mut n = tag_no;
            while n > 0b01111111 {
                current.push((n as u8 & 0b1111111) | 0b10000000);
                n >>= 7;
            }
            current.push(n as u8);
        }

        let len = contents.len()
            + match prefix {
                Some(_) => 1,
                None => 0,
            };
        if len < 0b10000000 {
            current.push(len as u8);
        } else {
            let mut rest = len;
            let mut n = 0;
            while rest > 0 {
                rest >>= 8;
                n += 1;
            }
            current.push(n | 0b10000000);
            for i in 0..n {
                current.push(((len >> ((n - i - 1) * 8)) & 0xFF) as u8);
            }
        }

        if let Some(val) = prefix {
            current.push(val);
        }
        current.extend_from_slice(contents);
    }

    pub fn end(&mut self) {
        let current = self.stack.pop().unwrap();
        let parent = self.stack.last_mut().unwrap();

        let len = current.len();
        if len < 0b10000000 {
            parent.push(len as u8);
        } else {
            let mut rest = len;
            let mut n = 0;
            while rest > 0 {
                rest >>= 8;
                n += 1;
            }
            parent.push(n | 0b10000000);
            for i in 0..n {
                parent.push(((len >> ((n - i - 1) * 8)) & 0xFF) as u8);
            }
        }

        parent.extend_from_slice(&current);
    }

    pub fn build(mut self) -> Vec<u8> {
        self.stack.remove(0)
    }
}
