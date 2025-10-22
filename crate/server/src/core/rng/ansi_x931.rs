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
        let mut key = [0u8; 32];
        let mut v = [0u8; 16];
        let mut dt = [0u8; 16];
        // Seed from OS RNG
        let _ = rand_bytes(&mut key);
        let _ = rand_bytes(&mut v);
        let _ = rand_bytes(&mut dt);
        Self { key, v, dt }
    }

    /// Reseed with additional data (XOR mix-in for simplicity)
    pub(crate) fn reseed(&mut self, additional_input: &[u8]) {
        for (i, b) in additional_input.iter().enumerate() {
            self.key[i % 32] ^= *b;
            self.v[i % 16] ^= *b;
        }
    }

    fn encrypt_block(&self, input: &[u8; 16]) -> Result<[u8; 16], openssl::error::ErrorStack> {
        let mut c = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, &self.key, None)?;
        c.pad(false);
        let mut buf = [0u8; 32];
        let mut count = c.update(input, &mut buf)?;
        count += c.finalize(&mut buf[count..])?;
        debug_assert!(count >= 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&buf[..16]);
        Ok(out)
    }

    /// Generate bytes using AES-256-ECB on dt and v, updating state between blocks.
    pub(crate) fn generate(&mut self, out: &mut [u8]) -> Result<(), openssl::error::ErrorStack> {
        let mut offset = 0usize;
        while offset < out.len() {
            // E_K(DT)
            let ek_dt = self.encrypt_block(&self.dt)?;

            // R = E_K(V XOR E_K(DT))
            let mut x = [0u8; 16];
            for i in 0..16 {
                x[i] = self.v[i] ^ ek_dt[i];
            }
            let rblk = self.encrypt_block(&x)?;

            // copy R to out
            let to_copy = core::cmp::min(16, out.len() - offset);
            out[offset..offset + to_copy].copy_from_slice(&rblk[..to_copy]);
            offset += to_copy;

            // V = E_K(R XOR E_K(DT))
            let mut y = [0u8; 16];
            for i in 0..16 {
                y[i] = rblk[i] ^ ek_dt[i];
            }
            let vnew = self.encrypt_block(&y)?;
            self.v.copy_from_slice(&vnew);

            // Update DT = DT + 1 (128-bit increment)
            for i in (0..16).rev() {
                let (nv, carry) = self.dt[i].overflowing_add(1);
                self.dt[i] = nv;
                if !carry {
                    break;
                }
            }
        }
        Ok(())
    }
}
