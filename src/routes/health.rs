use actix_web::{HttpResponse, Responder, get};

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Health check successful", body = String)
    )
)]
#[get("/health")]
pub async fn healthcheck_handler() -> impl Responder {
    HttpResponse::Ok().message_body("ok")
}

#[cfg(test)]
mod tests {
    use actix_web::{App, body::MessageBody, test};

    use super::*;

    #[actix_web::test]
    async fn test_healthcheck_get() {
        let app = test::init_service(App::new().service(healthcheck_handler)).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        assert!(resp.into_body().try_into_bytes().unwrap() == "ok");
    }
}
