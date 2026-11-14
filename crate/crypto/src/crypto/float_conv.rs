//! Integer ↔ `f64` conversions reproducing the semantics of `as` casts, for the
//! float arithmetic done on integers by anonymization and FF1.

use num_traits::ToPrimitive;

/// `i64` → nearest `f64` (round-to-nearest-even, identical to `as f64`).
pub(crate) fn i64_to_f64(value: i64) -> f64 {
    value.to_f64().unwrap_or(f64::NAN)
}

/// `usize` → nearest `f64` (round-to-nearest-even, identical to `as f64`).
pub(crate) fn usize_to_f64(value: usize) -> f64 {
    value.to_f64().unwrap_or(f64::NAN)
}

/// `f64` → `i64` truncating toward zero and saturating, identical to `as i64`:
/// NaN → 0, below `i64::MIN` → `i64::MIN`, above `i64::MAX` → `i64::MAX`.
pub(crate) fn f64_to_i64_saturating(value: f64) -> i64 {
    value.trunc().to_i64().unwrap_or_else(|| {
        if value.is_nan() {
            0
        } else if value.is_sign_negative() {
            i64::MIN
        } else {
            i64::MAX
        }
    })
}

/// `f64` → `usize` truncating toward zero and saturating, identical to `as usize`:
/// NaN and negatives → 0, above `usize::MAX` → `usize::MAX`.
pub(crate) fn f64_to_usize_saturating(value: f64) -> usize {
    value.trunc().to_usize().unwrap_or_else(|| {
        if value.is_nan() || value.is_sign_negative() {
            0
        } else {
            usize::MAX
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{f64_to_i64_saturating, f64_to_usize_saturating, i64_to_f64, usize_to_f64};

    // Expected values are those of the `as` casts these helpers replace.
    #[test]
    fn float_conv_matches_as_casts() {
        let two_pow_53_plus_one: i64 = (1 << 53) + 1;
        assert_eq!(i64_to_f64(0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(i64_to_f64(-1).to_bits(), (-1.0_f64).to_bits());
        assert_eq!(
            i64_to_f64(two_pow_53_plus_one).to_bits(),
            9_007_199_254_740_992.0_f64.to_bits()
        );
        assert_eq!(
            i64_to_f64(i64::MAX).to_bits(),
            9_223_372_036_854_775_808.0_f64.to_bits()
        );
        assert_eq!(
            i64_to_f64(i64::MIN).to_bits(),
            (-9_223_372_036_854_775_808.0_f64).to_bits()
        );
        assert_eq!(usize_to_f64(0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(
            usize_to_f64(1 << 53).to_bits(),
            9_007_199_254_740_992.0_f64.to_bits()
        );

        assert_eq!(f64_to_i64_saturating(0.0), 0);
        assert_eq!(f64_to_i64_saturating(0.5_f64.round()), 1);
        assert_eq!(f64_to_i64_saturating((-0.5_f64).round()), -1);
        assert_eq!(f64_to_i64_saturating(1.5_f64.round()), 2);
        assert_eq!(f64_to_i64_saturating((-1.5_f64).round()), -2);
        assert_eq!(f64_to_i64_saturating(-1.9), -1);
        assert_eq!(f64_to_i64_saturating(i64_to_f64(i64::MAX)), i64::MAX);
        assert_eq!(f64_to_i64_saturating(i64_to_f64(i64::MIN)), i64::MIN);
        assert_eq!(f64_to_i64_saturating(1e300), i64::MAX);
        assert_eq!(f64_to_i64_saturating(-1e300), i64::MIN);
        assert_eq!(f64_to_i64_saturating(f64::NAN), 0);
        assert_eq!(f64_to_i64_saturating(f64::INFINITY), i64::MAX);
        assert_eq!(f64_to_i64_saturating(f64::NEG_INFINITY), i64::MIN);

        assert_eq!(f64_to_usize_saturating(0.0), 0);
        assert_eq!(f64_to_usize_saturating(1.5_f64.round()), 2);
        assert_eq!(f64_to_usize_saturating(2.9), 2);
        assert_eq!(f64_to_usize_saturating(-0.5), 0);
        assert_eq!(f64_to_usize_saturating(-1.5), 0);
        assert_eq!(f64_to_usize_saturating(1e300), usize::MAX);
        assert_eq!(f64_to_usize_saturating(f64::NAN), 0);
        assert_eq!(f64_to_usize_saturating(f64::INFINITY), usize::MAX);
        assert_eq!(f64_to_usize_saturating(f64::NEG_INFINITY), 0);
    }
}
