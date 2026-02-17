use crate::DbConn;
use crate::config::Config;
use axum::extract::FromRef;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbConn,
    pub config: Config,
}

impl FromRef<AppState> for DbConn {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Config {
        state.config.clone()
    }
}
