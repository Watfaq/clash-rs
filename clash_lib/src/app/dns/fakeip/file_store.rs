use super::Store;

pub struct FileStore;

impl FileStore {
    pub fn new() -> Self {
        Self
    }
}

impl Store for FileStore {
    fn get_by_host(&mut self, _host: &str) -> Option<std::net::IpAddr> {
        todo!()
    }

    fn pub_by_host(&mut self, _host: &str, _ip: std::net::IpAddr) {
        todo!()
    }

    fn get_by_ip(&mut self, _ip: std::net::IpAddr) -> Option<String> {
        todo!()
    }

    fn put_by_ip(&mut self, _ip: std::net::IpAddr, _host: &str) {
        todo!()
    }

    fn del_by_ip(&mut self, _ip: std::net::IpAddr) {
        todo!()
    }

    fn exist(&mut self, _ip: std::net::IpAddr) -> bool {
        todo!()
    }

    fn copy_to(&self, _store: &mut Box<dyn Store>) {
        todo!()
    }
}
