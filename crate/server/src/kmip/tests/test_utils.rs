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
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    kmip::kmip_server::KMSServer, kmip_endpoint, middlewares::auth::Auth, result::KResult,
};

/// Test auth0 token (expired) -
/// bnjjj: I know it's ugly but it's easy and sufficient for now
pub static AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlRWdk5xTEtoUHhUSGdhYUNGRGRoSSJ9.eyJnaXZlbl9uYW1lIjoiTGFldGl0aWEiLCJmYW1pbHlfbmFtZSI6Ikxhbmdsb2lzIiwibmlja25hbWUiOiJsYWV0aXRpYS5sYW5nbG9pcyIsIm5hbWUiOiJMYWV0aXRpYSBMYW5nbG9pcyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp5UEJsSnpqRzNuMWZLLXNyS0ptdUVkYklUX29QRmhVbTd2T2dVWD1zOTYtYyIsImxvY2FsZSI6ImZyIiwidXBkYXRlZF9hdCI6IjIwMjEtMTItMjFUMDk6MjE6NDkuMDgxWiIsImVtYWlsIjoibGFldGl0aWEubGFuZ2xvaXNAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9kZXYtMW1ic2JtaW4udXMuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTA4NTgwMDU3NDAwMjkxNDc5ODQyIiwiYXVkIjoiYUZqSzJvTnkwR1RnNWphV3JNYkJBZzV0bjRIV3VJN1ciLCJpYXQiOjE2NDAwNzg1MTQsImV4cCI6MTY0MDExNDUxNCwibm9uY2UiOiJha0poV2xoMlRsTm1lRTVtVFc0NFJHSk5VVEl5WW14aVJUTnVRblV1VEVwa2RrTnFVa2R5WkdoWFdnPT0ifQ.Q4tCzvJTNxmDhIYOJbjsqupdQkWg29Ny0B8njEfSrLVXNaRMFE99eSXedCBaXSMBnZ9GuCV2Z1MAZL8ZjTxqPP_VYCnc2QufG1k1XZg--6Q48pPdpUBXu2Ny1eatwiDrRvgQfUHkiM8thUAOb4bXxGLrtQKlO_ePOehDbEOjfd11aVm3pwyVqj1v6Ki1D5QJsOHtkkpLMinmmyGDtmdHH2YXseZNHGUY7PWZ6DelpJaxI48W5FNDY4b0sJlzaJqdIcoOX7EeP1pfFoHVeZAo5mWyuDev2OaPYKeqpga4PjqHcFT0m1rQoWQHmfGr3EkA3w8NXmKnZmEbQcLLgcCATw";

pub async fn test_app()
-> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let kms_server = Arc::new(
        KMSServer::instantiate()
            .await
            .expect("cannot instantiate KMS server"),
    );

    test::init_service(
        App::new()
            .wrap(Auth)
            .app_data(Data::new(kms_server.clone()))
            .service(kmip_endpoint::kmip)
            .service(kmip_endpoint::access_insert)
            .service(kmip_endpoint::access_delete),
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
        .insert_header(("Authorization", format!("Bearer {}", AUTH0_TOKEN)))
        .set_json(&to_ttlv(&operation)?)
        .to_request();
    let body = test::call_and_read_body(&app, req).await;
    let json: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(&json)?;
    Ok(result)
}
