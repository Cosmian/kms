use chrono::{DateTime, Datelike, TimeZone, Timelike};
use rand_distr::num_traits::Pow;

use super::{AnoError, TimeUnit, datetime_to_rfc3339};

/// The `NumberAggregator` is a data anonymization technique used to round
/// sensitive measurements to the desired power of ten.
///
/// Example usage:
///
/// ```
/// use cloudproof_anonymization::core::NumberAggregator;
///
/// let num_agg = NumberAggregator::new(2).unwrap();
/// let anonymized_float = num_agg.apply_on_float(1234.5678); // returns "1200"
/// let anonymized_int = num_agg.apply_on_int(56789); // returns "56800"
/// ```
pub struct NumberAggregator {
    power_of_ten_exponent: i32,
}

impl NumberAggregator {
    /// Creates a new instance of `NumberAggregator`.
    ///
    /// # Arguments
    ///
    /// * `power_of_ten_exponent` - The power of ten to round the numbers to.
    pub fn new(power_of_ten_exponent: i32) -> Result<Self, AnoError> {
        // exponent cannot be greater than 308 (https://doc.rust-lang.org/std/primitive.f64.html#associatedconstant.MAX_10_EXP)
        if power_of_ten_exponent > f64::MAX_10_EXP {
            return Err(AnoError::AnonymizationError(format!(
                "Exponent must be lower than {}, given {power_of_ten_exponent}.",
                f64::MAX_10_EXP,
            )));
        }
        // Prevent very negative exponents that would allocate huge strings in format!
        if power_of_ten_exponent < -(f64::MAX_10_EXP) {
            return Err(AnoError::AnonymizationError(format!(
                "Exponent must be greater than {}, given {power_of_ten_exponent}.",
                -(f64::MAX_10_EXP),
            )));
        }
        Ok(Self {
            power_of_ten_exponent,
        })
    }

    /// Rounds a floating point number to the desired power of ten.
    ///
    /// # Arguments
    ///
    /// * `data` - The floating point number to round.
    ///
    /// # Returns
    ///
    /// A string representation of the rounded number.
    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> String {
        if self.power_of_ten_exponent < 0 {
            return format!("{:.1$}", data, -self.power_of_ten_exponent as usize);
        }
        let r = 10f64.pow(self.power_of_ten_exponent);
        format!("{}", (data / r).round() * r)
    }

    /// Rounds an integer to the desired power of ten.
    ///
    /// # Arguments
    ///
    /// * `data` - The integer to round.
    ///
    /// # Returns
    ///
    /// A string representation of the rounded number.
    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> String {
        let r = 10f64.pow(self.power_of_ten_exponent);
        format!("{:.0}", (data as f64 / r).round() * r)
    }
}

/// A data anonymization technique to round dates to the unit of time specified.
///
/// Example usage:
///
/// ```
/// use cloudproof_anonymization::core::{DateAggregator, TimeUnit};
///
/// let aggregator = DateAggregator::new(TimeUnit::Hour);
/// let result = aggregator.apply_on_date("2022-04-28T14:30:00Z"); // returns "2022-04-28T14:00:00+00:00"
/// ```
pub struct DateAggregator {
    time_unit: TimeUnit,
}

impl DateAggregator {
    /// Creates a new instance of `DateAggregator` with the provided time unit.
    ///
    /// # Arguments
    ///
    /// * `time_unit`: The unit of time to round the date to.
    #[must_use]
    pub fn new(time_unit: TimeUnit) -> Self {
        Self { time_unit }
    }

    /// Applies the date rounding to the provided date string based on the unit
    /// of time.
    ///
    /// # Arguments
    ///
    /// * `date_str`: A string representing the date to be rounded.
    ///
    /// # Returns
    ///
    /// The rounded date in RFC 3339 if the rounding is successful,
    /// otherwise returns an `AnoError`.
    pub fn apply_on_date(&self, date_str: &str) -> Result<String, AnoError> {
        // Parse the date string into a DateTime.
        let date = DateTime::parse_from_rfc3339(date_str)?;
        let tz = date.timezone();

        let (y, mo, d, h, mi, s) = match self.time_unit {
            TimeUnit::Second => (
                date.year(),
                date.month(),
                date.day(),
                date.hour(),
                date.minute(),
                date.second(),
            ),
            TimeUnit::Minute => (
                date.year(),
                date.month(),
                date.day(),
                date.hour(),
                date.minute(),
                0,
            ),
            TimeUnit::Hour => (date.year(), date.month(), date.day(), date.hour(), 0, 0),
            TimeUnit::Day => (date.year(), date.month(), date.day(), 0, 0, 0),
            TimeUnit::Month => (date.year(), date.month(), 1, 0, 0, 0),
            TimeUnit::Year => (date.year(), 1, 1, 0, 0, 0),
        };

        datetime_to_rfc3339(tz.with_ymd_and_hms(y, mo, d, h, mi, s), date_str)
    }
}

/// A data anonymization method that scales individual values while keeping the
/// overall distribution of the data.
pub struct NumberScaler {
    mean: f64,
    std_deviation: f64,
    scale: f64,
    translate: f64,
}

impl NumberScaler {
    /// Creates a new `NumberScaler` instance.
    ///
    /// # Arguments
    ///
    /// * `mean`: The mean of the data distribution.
    /// * `std_deviation`: The standard deviation of the data distribution. Must be non-zero.
    /// * `scale`: The scaling factor.
    /// * `translate`: The translation factor.
    pub fn new(
        mean: f64,
        std_deviation: f64,
        scale: f64,
        translate: f64,
    ) -> Result<Self, AnoError> {
        if std_deviation == 0.0 {
            return Err(AnoError::AnonymizationError(
                "Standard deviation must be non-zero to avoid division by zero.".to_owned(),
            ));
        }
        Ok(Self {
            mean,
            std_deviation,
            scale,
            translate,
        })
    }

    /// Applies the scaling and translation on a floating-point number.
    ///
    /// # Arguments
    ///
    /// * `data`: A floating-point number to be scaled.
    ///
    /// # Returns
    ///
    /// The scaled value.
    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> f64 {
        // Apply scaling and translation to the normalized data
        let normalized_data = (data - self.mean) / self.std_deviation;
        normalized_data.mul_add(self.scale, self.translate)
    }

    /// Applies the scaling and translation on an integer.
    ///
    /// # Arguments
    ///
    /// * `data`: An integer to be scaled.
    ///
    /// # Returns
    ///
    /// The scaled value as an integer.
    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> i64 {
        self.apply_on_float(data as f64).round() as i64
    }
}
