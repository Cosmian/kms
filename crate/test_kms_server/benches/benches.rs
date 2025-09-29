#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    let_underscore_drop,
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_value
)]

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
#[cfg(feature = "non-fips")]
use rsa_benches::bench_encrypt_rsa_pkcs15_parametrized;
use rsa_benches::{
    bench_encrypt_rsa_aes_key_wrap_parametrized, bench_encrypt_rsa_oaep_parametrized,
};
use symmetric_benches::bench_encrypt_aes_parametrized;

#[cfg(feature = "non-fips")]
use crate::rsa_benches::{
    bench_rsa_pkcs_v15_decrypt_2048, bench_rsa_pkcs_v15_decrypt_4096,
    bench_rsa_pkcs_v15_encrypt_2048, bench_rsa_pkcs_v15_encrypt_4096,
};
#[cfg(feature = "non-fips")]
use crate::symmetric_benches::{
    bench_decrypt_chacha20_128_poly1305, bench_decrypt_chacha20_256_poly1305,
    bench_encrypt_chacha20_128_poly1305, bench_encrypt_chacha20_256_poly1305,
};
use crate::{
    rsa_benches::{
        bench_rsa_create_keypair, bench_rsa_key_wrp_decrypt_2048, bench_rsa_key_wrp_decrypt_4096,
        bench_rsa_key_wrp_encrypt_2048, bench_rsa_key_wrp_encrypt_4096,
        bench_rsa_oaep_decrypt_2048, bench_rsa_oaep_decrypt_4096, bench_rsa_oaep_encrypt_2048,
        bench_rsa_oaep_encrypt_4096,
    },
    symmetric_benches::{
        bench_create_symmetric_key, bench_decrypt_aes_128_gcm, bench_decrypt_aes_256_gcm,
        bench_decrypt_aes_256_gcm_100000, bench_encrypt_aes_128_gcm, bench_encrypt_aes_256_gcm,
        bench_encrypt_aes_256_gcm_100000,
    },
};

mod rsa_benches;
mod symmetric_benches;

criterion_main!(
    symmetric_key_benches,
    symmetric_encryption_benches,
    bulk_symmetric_encryption_benches,
    rsa_keypair_benches,
    rsa_encryption_benches,
    symmetric_encryption_benches_parametrized
);

criterion_group!(
    name = symmetric_key_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
         bench_create_symmetric_key,
);

// Include ChaCha benches only for non-FIPS builds
#[cfg(feature = "non-fips")]
criterion_group!(
    name = symmetric_encryption_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_aes_128_gcm,
        bench_encrypt_aes_256_gcm,
        bench_decrypt_aes_128_gcm,
        bench_decrypt_aes_256_gcm,
        bench_encrypt_chacha20_128_poly1305,
        bench_encrypt_chacha20_256_poly1305,
        bench_decrypt_chacha20_128_poly1305,
        bench_decrypt_chacha20_256_poly1305
);
#[cfg(not(feature = "non-fips"))]
criterion_group!(
    name = symmetric_encryption_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_aes_128_gcm,
        bench_encrypt_aes_256_gcm,
        bench_decrypt_aes_128_gcm,
        bench_decrypt_aes_256_gcm
);

criterion_group!(
    name = bulk_symmetric_encryption_benches;
    config = Criterion::default().sample_size(15).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_aes_256_gcm_100000,
        bench_decrypt_aes_256_gcm_100000
);

criterion_group!(
    name = rsa_keypair_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
         bench_rsa_create_keypair,
);

// Include RSA PKCS#1 v1.5 benches only for non-FIPS builds
#[cfg(feature = "non-fips")]
criterion_group!(
    name = rsa_encryption_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_rsa_pkcs_v15_encrypt_2048,
        bench_rsa_pkcs_v15_encrypt_4096,
        bench_rsa_pkcs_v15_decrypt_2048,
        bench_rsa_pkcs_v15_decrypt_4096,
        bench_rsa_oaep_encrypt_2048,
        bench_rsa_oaep_encrypt_4096,
        bench_rsa_oaep_decrypt_2048,
        bench_rsa_oaep_decrypt_4096,
        bench_rsa_key_wrp_encrypt_2048,
        bench_rsa_key_wrp_encrypt_4096,
        bench_rsa_key_wrp_decrypt_2048,
        bench_rsa_key_wrp_decrypt_4096,
);
#[cfg(not(feature = "non-fips"))]
criterion_group!(
    name = rsa_encryption_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_rsa_oaep_encrypt_2048,
        bench_rsa_oaep_encrypt_4096,
        bench_rsa_oaep_decrypt_2048,
        bench_rsa_oaep_decrypt_4096,
        bench_rsa_key_wrp_encrypt_2048,
        bench_rsa_key_wrp_encrypt_4096,
        bench_rsa_key_wrp_decrypt_2048,
        bench_rsa_key_wrp_decrypt_4096,
);

// This parametrized group is PKCS#1 v1.5 only
#[cfg(feature = "non-fips")]
criterion_group!(
    name = rsa_encryption_parametrized_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_rsa_pkcs_v15_encrypt_4096,
);

criterion_group!(
    name = symmetric_encryption_benches_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_aes_parametrized,
);
#[cfg(feature = "non-fips")]
criterion_group!(
    name = encrypt_rsa_pkcs15_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_rsa_pkcs15_parametrized,
);
criterion_group!(
    name = encrypt_rsa_oaep_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_rsa_oaep_parametrized,
);
criterion_group!(
    name = encrypt_rsa_aes_key_wrap_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_rsa_aes_key_wrap_parametrized,
);
