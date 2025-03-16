#[derive(Debug, Clone)]
pub struct Config {
    pub pds_admin_password: String,
    pub pds_endpoint: String,
    pub database_url: String,
    pub db_min_idle: String,
    pub worker_count: usize,
}
