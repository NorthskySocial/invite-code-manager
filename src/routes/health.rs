use actix_web::{HttpResponse, Responder, get};

#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}
