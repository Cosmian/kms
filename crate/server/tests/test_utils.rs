use std::sync::Arc;

use actix_http::Request;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test,
    web::Data,
    App,
};
use cosmian_kmip::kmip::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV};
use cosmian_kms_server::{middlewares::auth::Auth0, result::KResult, routes::endpoint, KMSServer};
use serde::{de::DeserializeOwned, Serialize};

/// Test auth0 token (expired) -
/// bnjjj: I know it's ugly but it's easy and sufficient for now
pub static AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlJqaTdXRDRaZWJZaVh0bXFoOWUyeSJ9.eyJuaWNrbmFtZSI6ImFsaWNlIiwibmFtZSI6ImFsaWNlQGNvc21pYW4uY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzUzYTU2MTY5MmFiZWRkZWI4NTE5YzFjNjMxNTczNzA3P3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYWwucG5nIiwidXBkYXRlZF9hdCI6IjIwMjMtMDEtMjdUMTQ6MDA6MjEuNjUyWiIsImVtYWlsIjoiYWxpY2VAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9jb25zb2xlLWRldi5ldS5hdXRoMC5jb20vIiwiYXVkIjoiYngyV2xMclM3cXIzNWl5TnFVVlRzOWpNbzgzNG84bUMiLCJpYXQiOjE2NzQ4MjgyOTIsImV4cCI6MTY3NDg2NDI5Miwic3ViIjoiYXV0aDB8NjMwYzkyMmEwNjc3ZjVmOTUzMjJhYjVlIiwic2lkIjoiaFV1MzlGNlhuX0VYQ1ljcldNQUtBWndLYTdlLWlpczQiLCJub25jZSI6ImNtOTZTWEpZY1U1SE9FdFJVV1oxU3pOVFpHSXpVRlJ6V1RGNWRVcDJVa0o1VDJjd1dtWmthVll4YXc9PSJ9.jTV4sFgXAoOIA7d_Xz4W8f8GmGwCqFkO0WVuuH6HyPxf093uWzo0DdjGY9jG7T3Jhxgf9uDAZEh-6txb43_uPGpt2N3uGn00B7XGI05RqzSgCX7e2pVU6SiFpRZF6uchdHIIxPjmAqEheZ3fTeQndg2BfEuO0XTUH-Og3w_hsnK0k20B1zDeZc1XRZ_UEqkmqRym66f3tbj1QbDb-Ogtf1t5AupRRDzTR8VgC6Z6PW5sTCpdJ49Zd-gHNZ7yKJOTw39wG26791uKganovJDqYL12UfForCBrXNE-6QtmUT-Adm_duKezAqEKm_9cZI4BTNpy3tLr2vW9HMeaUtr9hQ";

pub async fn test_app()
-> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let kms_server = Arc::new(
        KMSServer::instantiate()
            .await
            .expect("cannot instantiate KMS server"),
    );

    test::init_service(
        App::new()
            .wrap(Auth0)
            .app_data(Data::new(kms_server.clone()))
            .service(endpoint::kmip)
            .service(endpoint::insert_access)
            .service(endpoint::delete_access),
    )
    .await
}

pub async fn post<B, O, R, S>(app: &S, operation: O) -> KResult<R>
where
    O: Serialize,
    R: DeserializeOwned,
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::post()
        .uri("/kmip/2_1")
        .insert_header(("Authorization", format!("Bearer {AUTH0_TOKEN}")))
        .set_json(to_ttlv(&operation)?)
        .to_request();
    let body = test::call_and_read_body(&app, req).await;
    let json: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(&json)?;
    Ok(result)
}
