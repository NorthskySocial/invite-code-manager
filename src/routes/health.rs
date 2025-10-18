use actix_web::{get, HttpResponse, Responder};

#[get("/health")]
pub async fn healthcheck_handler() -> impl Responder {
    HttpResponse::Ok().message_body("ok")
}

#[cfg(test)]
mod tests {
    use actix_web::{body::MessageBody, test, App};

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
