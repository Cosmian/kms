use chrono::{DateTime, TimeZone};
use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::{CryptoRng, Rng};
use rand_distr::{num_traits::Float, Distribution, Normal, Standard, StandardNormal, Uniform};

use super::datetime_to_rfc3339;
use crate::{ano_error, core::AnoError};

// Represent the different Noise methods.
pub enum NoiseMethod<F>
where
    F: Float + rand_distr::uniform::SampleUniform,
    StandardNormal: Distribution<F>,
{
    Gaussian(Normal<F>),
    Laplace(Laplace<F>),
    Uniform(Uniform<F>),
}

impl<F> NoiseMethod<F>
where
    F: Float + rand_distr::uniform::SampleUniform,
    Standard: Distribution<F>,
    StandardNormal: Distribution<F>,
{
    fn sample<R: CryptoRng + Rng + ?Sized>(&self, rng: &mut R) -> F {
        match self {
            Self::Gaussian(distr) => distr.sample(rng),
            Self::Laplace(distr) => distr.sample(rng),
            Self::Uniform(distr) => distr.sample(rng),
        }
    }
}

/// A Laplace distribution, used to generate random numbers following the
/// Laplace distribution.
///
/// # Example
/// ```
/// use cloudproof_anonymization::core::Laplace;
/// use rand::prelude::*;
/// use rand_distr::Distribution;
///
/// let laplace = Laplace::new(0.0, 1.0).expect("beta is positive");
/// let mut rng = thread_rng();
///
/// let v = laplace.sample(&mut rng);
/// ```
pub struct Laplace<F> {
    mean: F,
    beta: F,
}

impl<F: Float> Laplace<F> {
    /// Creates a new Laplace distribution with a given mean and beta parameter.
    ///
    /// # Arguments
    ///
    /// * `mean` - The mean of the Laplace distribution.
    /// * `beta` - The scale parameter of the Laplace distribution. Must be strictly positive.
    pub fn new(mean: F, beta: F) -> Result<Self, AnoError> {
        if beta <= F::zero() {
            return Err(ano_error!(
                "Laplace beta must be strictly positive (got a non-positive value)."
            ));
        }
        Ok(Self { mean, beta })
    }
}

impl<F: Float> Distribution<F> for Laplace<F>
where
    Standard: Distribution<F>,
{
    /// Generates a random number following the Laplace distribution.
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator used to generate the number.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        // Clamp p away from 0 to prevent ln(0) = -inf.
        // rng.gen() samples [0, 1); p == 0 is possible but astronomically rare.
        let p: F = {
            let raw: F = rng.gen();
            if raw == F::zero() {
                F::epsilon()
            } else {
                raw
            }
        };
        if rng.gen_bool(0.5) {
            self.mean - self.beta * F::ln(F::one() - p)
        } else {
            self.mean + self.beta * F::ln(p)
        }
    }
}

pub struct NoiseGenerator<F>
where
    F: Float + rand_distr::uniform::SampleUniform,
    rand_distr::StandardNormal: rand_distr::Distribution<F>,
{
    method: NoiseMethod<F>,
    rng: CsRng,
}

impl<F> NoiseGenerator<F>
where
    F: Float + rand_distr::uniform::SampleUniform,
    Standard: Distribution<F>,
    StandardNormal: Distribution<F>,
{
    /// Instantiate a `NoiseGenerator` using mean and standard deviation.
    ///
    /// # Arguments
    ///
    /// * `method_name` - the noise distribution to use ("Gaussian" or
    ///   "Laplace")
    /// * `mean` - mean of the noise distribution
    /// * `std_dev` - the standard deviation of the noise distribution.
    pub fn new_with_parameters(method_name: &str, mean: F, std_dev: F) -> Result<Self, AnoError> {
        if std_dev.is_zero() || std_dev.is_sign_negative() {
            return Err(ano_error!(
                "Standard Deviation must be greater than 0 to generate noise."
            ));
        }

        // Select the appropriate distribution method
        let method = match method_name {
            "Gaussian" => Ok(NoiseMethod::Gaussian(Normal::new(mean, std_dev)?)),
            "Laplace" => {
                // σ = β * sqrt(2)
                let beta = std_dev
                    / F::from(2)
                        .ok_or_else(|| ano_error!("Internal float conversion error."))?
                        .sqrt();
                Ok(NoiseMethod::Laplace(Laplace::<F>::new(mean, beta)?))
            }
            _ => Err(ano_error!("{method_name} is not a supported distribution.")),
        }?;
        Ok(Self {
            method,
            rng: CsRng::from_entropy(),
        })
    }

    /// Instantiate a `NoiseGenerator` with bound constraints.
    ///
    /// # Arguments
    ///
    /// * `method_name`: The noise distribution to use ("Uniform", "Gaussian",
    ///   or "Laplace").
    /// * `min_bound`: The lower bound of the range of possible generated noise
    ///   values.
    /// * `max_bound`: The upper bound of the range of possible generated noise
    ///   values.
    pub fn new_with_bounds(
        method_name: &str,
        min_bound: F,
        max_bound: F,
    ) -> Result<Self, AnoError> {
        if min_bound >= max_bound {
            return Err(ano_error!("Min bound must be inferior to Max bound."));
        }

        let two = F::from(2).ok_or_else(|| ano_error!("Internal float conversion error."))?;

        // Select the appropriate distribution method
        let method = match method_name {
            "Gaussian" => {
                let mean = (max_bound + min_bound) / two;
                // 5σ => 99.99994% of values will be in the bounds
                let std_dev = (mean - min_bound)
                    / F::from(5).ok_or_else(|| ano_error!("Internal float conversion error."))?;
                Ok(NoiseMethod::Gaussian(Normal::new(mean, std_dev)?))
            }
            "Laplace" => {
                let mean = (max_bound + min_bound) / two;
                // confidence interval at 1-a: μ ± β * ln(1/a)
                let beta = (mean - min_bound)
                    / -F::ln(
                        F::from(0.00005_f64)
                            .ok_or_else(|| ano_error!("Internal float conversion error."))?,
                    );
                Ok(NoiseMethod::Laplace(Laplace::<F>::new(mean, beta)?))
            }
            "Uniform" => Ok(NoiseMethod::Uniform(Uniform::new(min_bound, max_bound))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self {
            method,
            rng: CsRng::from_entropy(),
        })
    }

    /// Adds noise generated from a chosen distribution to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - A single float value to which noise will be added.
    ///
    /// # Returns
    ///
    /// Original data with added noise
    pub fn apply_on_float(&mut self, data: F) -> F {
        // Sample noise and add it to the raw data
        let noise = self.method.sample(&mut self.rng);
        data + noise
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of floats to add noise to.
    /// * `factors`: Factors to scale the noise with, one for each data point.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_floats(
        &mut self,
        data: &[F],
        factors: &[F],
    ) -> Result<Vec<F>, AnoError> {
        if data.len() != factors.len() {
            return Err(ano_error!(
                "data and factors must have the same length ({} vs {}).",
                data.len(),
                factors.len()
            ));
        }
        // Sample noise once and scale per entry
        let noise = self.method.sample(&mut self.rng);
        Ok(data
            .iter()
            .zip(factors.iter())
            .map(|(val, factor)| noise.mul_add(*factor, *val))
            .collect())
    }
}

impl NoiseGenerator<f64> {
    /// Adds noise generated from a chosen distribution to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - A single int value to which noise will be added.
    ///
    /// # Returns
    ///
    /// Original data with added noise
    pub fn apply_on_int(&mut self, data: i64) -> i64 {
        let res = self.apply_on_float(data as f64);
        res.round() as i64
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of ints to add noise to.
    /// * `factors`: Factors to scale the noise with.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_ints(
        &mut self,
        data: &[i64],
        factors: &[f64],
    ) -> Result<Vec<i64>, AnoError> {
        let input_floats: Vec<f64> = data.iter().map(|val: &i64| *val as f64).collect();
        Ok(self
            .apply_correlated_noise_on_floats(&input_floats, factors)?
            .iter()
            .map(|val| val.round() as i64)
            .collect())
    }

    /// Applies the selected noise method on a given date string.
    ///
    /// # Arguments
    ///
    /// * `date_str` -  - A date string in the RFC3339 format.
    ///
    /// # Returns
    ///
    ///  The resulting noisy date string
    pub fn apply_on_date(&mut self, date_str: &str) -> Result<String, AnoError> {
        let date = DateTime::parse_from_rfc3339(date_str)?;
        let tz = date.timezone();
        let date_unix = date.timestamp();
        let noisy_date_unix = self.apply_on_int(date_unix);
        datetime_to_rfc3339(tz.timestamp_opt(noisy_date_unix, 0), date_str)
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of dates string to add noise to.
    /// * `factors`: Factors to scale the noise with.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_dates(
        &mut self,
        data: &[&str],
        factors: &[f64],
    ) -> Result<Vec<String>, AnoError> {
        let (mut timestamps, mut timezones) = (
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
        );
        for date_str in data {
            match DateTime::parse_from_rfc3339(date_str) {
                Ok(date) => {
                    timestamps.push(date.timestamp());
                    timezones.push(date.timezone());
                }
                Err(e) => return Err(e.into()),
            }
        }

        self.apply_correlated_noise_on_ints(&timestamps, factors)?
            .into_iter()
            .enumerate()
            .map(|(i, val)| datetime_to_rfc3339(timezones[i].timestamp_opt(val, 0), data[i]))
            .collect()
    }
}
