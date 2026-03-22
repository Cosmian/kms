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
use sign_benches::{bench_ecdsa_sign_verify, bench_rsa_pss_sign_verify};
use symmetric_benches::bench_encrypt_aes_parametrized;

#[cfg(feature = "non-fips")]
use crate::rsa_benches::{
    bench_rsa_pkcs_v15_decrypt_2048, bench_rsa_pkcs_v15_decrypt_4096,
    bench_rsa_pkcs_v15_encrypt_2048, bench_rsa_pkcs_v15_encrypt_4096,
};
#[cfg(feature = "non-fips")]
use crate::sign_benches::{
    bench_create_ec_key_pair_non_fips, bench_ecdsa_secp256k1_sign_verify, bench_eddsa_sign_verify,
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
    sign_benches::bench_create_ec_key_pair,
    symmetric_benches::{
        bench_create_symmetric_key, bench_decrypt_aes_128_gcm, bench_decrypt_aes_256_gcm,
        bench_decrypt_aes_256_gcm_100000, bench_encrypt_aes_128_gcm, bench_encrypt_aes_256_gcm,
        bench_encrypt_aes_256_gcm_100000,
    },
};

mod rsa_benches;
mod sign_benches;
mod symmetric_benches;

// ── non-FIPS build includes all groups ───────────────────────────────────────
#[cfg(feature = "non-fips")]
criterion_main!(
    symmetric_key_benches,
    symmetric_encryption_benches,
    bulk_symmetric_encryption_benches,
    rsa_keypair_benches,
    rsa_encryption_benches,
    ec_keypair_benches,
    ec_keypair_non_fips_benches,
    sign_verify_benches,
    sign_verify_non_fips_benches,
    symmetric_encryption_benches_parametrized,
    encrypt_rsa_pkcs15_parametrized,
    encrypt_rsa_oaep_parametrized,
    encrypt_rsa_aes_key_wrap_parametrized,
);

// ── FIPS build excludes non-FIPS groups ─────────────────────────────────────
#[cfg(not(feature = "non-fips"))]
criterion_main!(
    symmetric_key_benches,
    symmetric_encryption_benches,
    bulk_symmetric_encryption_benches,
    rsa_keypair_benches,
    rsa_encryption_benches,
    ec_keypair_benches,
    sign_verify_benches,
    symmetric_encryption_benches_parametrized,
    encrypt_rsa_oaep_parametrized,
    encrypt_rsa_aes_key_wrap_parametrized,
);

// ═════════════════════════════════════════════════════════════════════════════
// Symmetric
// ═════════════════════════════════════════════════════════════════════════════

criterion_group!(
    name = symmetric_key_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
         bench_create_symmetric_key,
);

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
    name = symmetric_encryption_benches_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets =
        bench_encrypt_aes_parametrized,
);

// ═════════════════════════════════════════════════════════════════════════════
// RSA
// ═════════════════════════════════════════════════════════════════════════════

criterion_group!(
    name = rsa_keypair_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
         bench_rsa_create_keypair,
);

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

// ═════════════════════════════════════════════════════════════════════════════
// EC key creation + sign/verify
// ═════════════════════════════════════════════════════════════════════════════

criterion_group!(
    name = ec_keypair_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
        bench_create_ec_key_pair,
);
#[cfg(feature = "non-fips")]
criterion_group!(
    name = ec_keypair_non_fips_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
        bench_create_ec_key_pair_non_fips,
);

criterion_group!(
    name = sign_verify_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(30));
    targets =
        bench_ecdsa_sign_verify,
        bench_rsa_pss_sign_verify,
);
#[cfg(feature = "non-fips")]
criterion_group!(
    name = sign_verify_non_fips_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(30));
    targets =
        bench_eddsa_sign_verify,
        bench_ecdsa_secp256k1_sign_verify,
);
