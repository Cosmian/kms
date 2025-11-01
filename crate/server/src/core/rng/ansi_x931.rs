use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};

/// Minimal, stateful ANSI X9.31-style RNG using AES-256.
/// Note: This is a simplified construction suitable for test vectors; it is
/// not intended to replace a certified DRBG in production.
pub(crate) struct AnsiX931Rng {
    key: [u8; 32], // AES-256 key
    v: [u8; 16],   // internal state (V)
    dt: [u8; 16],  // date/time block
}

impl AnsiX931Rng {
    pub(crate) fn new() -> Self {
        let mut key = [0_u8; 32];
        let mut v = [0_u8; 16];
        let mut dt = [0_u8; 16];
        // Seed from OS RNG
        drop(rand_bytes(&mut key));
        drop(rand_bytes(&mut v));
        drop(rand_bytes(&mut dt));
        Self { key, v, dt }
    }

    /// Reseed with additional data (XOR mix-in for simplicity)
    pub(crate) fn reseed(&mut self, additional_input: &[u8]) {
        for (i, b) in additional_input.iter().enumerate() {
            if let Some(k) = self.key.get_mut(i % 32) {
                *k ^= *b;
            }
            if let Some(v) = self.v.get_mut(i % 16) {
                *v ^= *b;
            }
        }
    }

    fn encrypt_block(&self, input: &[u8; 16]) -> Result<[u8; 16], openssl::error::ErrorStack> {
        let mut c = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, &self.key, None)?;
        c.pad(false);
        let mut buf = [0_u8; 32];
        let mut count = c.update(input, &mut buf)?;
        // Constant safe range for finalize destination (ECB with 16B input writes at most 16+0 bytes)
        count += c.finalize(&mut buf[16..])?;
        debug_assert!(count >= 16);
        let mut out = [0_u8; 16];
        out.copy_from_slice(&buf[..16]);
        Ok(out)
    }

    /// Generate bytes using AES-256-ECB on dt and v, updating state between blocks.
    pub(crate) fn generate(&mut self, out: &mut [u8]) -> Result<(), openssl::error::ErrorStack> {
        let mut offset = 0_usize;
        while offset < out.len() {
            // E_K(DT)
            let ek_dt = self.encrypt_block(&self.dt)?;

            // R = E_K(V XOR E_K(DT))
            let mut x = [0_u8; 16];
            for ((xi, vi), ei) in x.iter_mut().zip(self.v.iter()).zip(ek_dt.iter()) {
                *xi = *vi ^ *ei;
            }
            let rblk = self.encrypt_block(&x)?;

            // copy R to out
            let to_copy = core::cmp::min(16, out.len() - offset);
            for (dst, src) in out.iter_mut().skip(offset).zip(rblk.iter()).take(to_copy) {
                *dst = *src;
            }
            offset += to_copy;

            // V = E_K(R XOR E_K(DT))
            let mut y = [0_u8; 16];
            for ((yi, ri), ei) in y.iter_mut().zip(rblk.iter()).zip(ek_dt.iter()) {
                *yi = *ri ^ *ei;
            }
            let vnew = self.encrypt_block(&y)?;
            self.v.copy_from_slice(&vnew);

            // Update DT = DT + 1 (128-bit increment)
            for b in self.dt.iter_mut().rev() {
                let (nv, carry) = b.overflowing_add(1);
                *b = nv;
                if !carry {
                    break;
                }
            }
        }
        Ok(())
    }
}
