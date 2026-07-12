#![allow(dead_code)]

use crate::{ProxyRequest, UserContext, msgs::squic::UserStats};

#[derive(Default, Clone)]
pub struct ProxyStatsAtm;

#[derive(Clone, Default)]
pub struct Observer;

impl Observer {
    pub fn new() -> Self {
        Self
    }

    pub async fn on_new_request(&self, _user_context: &UserContext) -> ProxyStatsAtm {
        ProxyStatsAtm
    }

    pub async fn remove_user(&self, _username: &str) {}

    pub async fn close_conn(&self, _username: &str) {}

    pub async fn get_conn_num(&self, _username: &str) -> usize {
        0
    }

    pub async fn get_user_stats(&self, _username: &str) -> UserStats {
        UserStats::default()
    }

    pub async fn get_all_stats(&self, _usernames: &[String]) -> Vec<UserStats> {
        Vec::new()
    }

    pub(crate) async fn wrap_request(&self, req: ProxyRequest) -> ProxyRequest {
        req
    }
}
