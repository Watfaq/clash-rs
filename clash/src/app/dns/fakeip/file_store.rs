use std::cell::RefCell;

use super::Store;

pub struct FileStore;

impl FileStore {
    pub fn new() -> Self {
        Self
    }
}

impl Store for FileStore {
    fn get_by_host(&mut self, host: &str) -> Option<std::net::IpAddr> {
        todo!()
    }

    fn pub_by_host(&mut self, host: &str, ip: std::net::IpAddr) {
        todo!()
    }

    fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        todo!()
    }

    fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        todo!()
    }

    fn del_by_ip(&mut self, ip: std::net::IpAddr) {
        todo!()
    }

    fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        todo!()
    }

    fn copy_to(&self, store: &mut RefCell<Box<dyn Store>>) {
        todo!()
    }
}
