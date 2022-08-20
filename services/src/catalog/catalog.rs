use std::{any::Any, collections::HashMap};

pub struct ServicesCatalog {
    pub services: HashMap<String, Box<dyn Any + Send + Sync>>,
}

#[allow(dead_code)]
impl ServicesCatalog {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    pub fn get<T: Any>(&self) -> Option<&T> {
        let service_name = std::any::type_name::<T>().to_owned();
        for (key, service_ptr) in self.services.iter() {
            if service_name == *(key) {
                let value_any = &*(*service_ptr);
                if let Some(service) = value_any.downcast_ref::<T>() {
                    return Some(service);
                } else {
                    return None;
                }
            }
        }
        return None;
    }

    pub fn register(&mut self, service_name: String, service: Box<dyn Any + Send + Sync>) {
        for (key, _) in self.services.iter() {
            if *(key) == service_name {
                return;
            }
        }
        self.services.insert(service_name, service);
    }
}

#[cfg(test)]
mod tests {
    use crate::core::service::Service;

    use super::*;

    struct MyService;
    impl MyService {
        fn new() -> Self {
            Self {}
        }
    }

    impl Service for MyService {
        fn name(&self) -> String {
            "My Service".to_owned()
        }
    }

    #[test]
    fn test_service_catalog() {
        let mut catalog = ServicesCatalog::new();
        catalog.register(
            std::any::type_name::<MyService>().to_string(),
            Box::new(MyService::new()),
        );
        assert_eq!(catalog.services.len(), 1);
        assert_eq!(catalog.get::<MyService>().unwrap().name(), "My Service");
    }

    #[test]
    fn test_traits() {
        assert_eq!(
            std::any::type_name::<MyService>(),
            "services::catalog::catalog::tests::MyService"
        );
    }

    #[test]
    fn test_arc_catalog() {
        let mut catalog = ServicesCatalog::new();
        catalog.register(
            std::any::type_name::<MyService>().to_string(),
            Box::new(MyService::new()),
        );
        let catalog1 = catalog;
        assert_eq!(catalog1.get::<MyService>().unwrap().name(), "My Service");
    }
}
