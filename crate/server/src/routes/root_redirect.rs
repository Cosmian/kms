use actix_web::{HttpResponse, get, http::header};

#[get("/")]
pub(crate) async fn root_redirect_to_ui() -> HttpResponse {
    HttpResponse::TemporaryRedirect()
        .insert_header((header::LOCATION, "/ui"))
        .finish()
}
