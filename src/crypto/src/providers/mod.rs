pub mod cek;
pub mod enc;
pub mod keys;
pub mod sig;

pub trait Tester<T> {
    fn add(&self) -> String {
        self.get()
    }

    fn get(&self) -> String;
}

pub struct TesterImp;

impl Tester<TesterImp> for TesterImp {
    fn get(&self) -> String {
        "".to_owned()
    }
}
