//! Implementation of Anti-Replay Algorithm without Bit Shifting
//! Based on RFC 6479
//!
//! # Examples
//! ```
//! # use nonce_window::SlidingWindow;
//!
//! let mut window = SlidingWindow::<u64, u64>::new(64);
//!
//! assert_eq!((), window.update(5).unwrap());
//! window.update(5).unwrap_err(); // reuse
//!
//! assert_eq!((), window.update(20).unwrap());
//! assert_eq!((), window.update(4).unwrap());
//! window.update(4).unwrap_err(); // reuse
//!
//! assert_eq!((), window.update(128).unwrap()); // advance window
//! let _unused_result = window.update(10); // may or may not return an error
//! window.update(10).unwrap_err(); // reuse
//! ```
//!
//! - A nonce will be accepted
//! if it is not less than the highest accepted nonce minus minimum_sliding_window_size
//! AND it has not been accepted before
//! - A nonce will be rejected if it has been accepted before
//! - A nonce that has not been accepted before
//! AND is less than the highest accepted nonce minus minimum_sliding_window_size
//! MAY be rejected

use std::{
	error::Error,
	fmt::{self, Debug, Display, Formatter},
	marker::PhantomData,
};

use num_traits::{FromPrimitive, PrimInt, Unsigned};

#[cfg(test)]
mod tests {
	use std::{fmt::Debug, hash::Hash};

	use num_traits::FromPrimitive;
	use rand::distributions::{Distribution, Uniform};

	use crate::{tests::model::ModelWindow, PrimUInt, SlidingWindow};

	mod model {
		use std::{collections::HashSet, hash::Hash, marker::PhantomData};

		use num_traits::FromPrimitive;

		use crate::{PrimUInt, ReplayedNonce};

		pub struct ModelWindow<B: PrimUInt, N: PrimUInt> {
			nonces: HashSet<N>,
			minimum_window_size: usize,
			max_nonce: Option<N>,
			_nonce_type: PhantomData<B>,
		}

		impl<B: PrimUInt, N: PrimUInt + Hash> ModelWindow<B, N> {
			pub fn new(minimum_window_size: usize) -> Self {
				Self {
					nonces: HashSet::with_capacity(minimum_window_size),
					minimum_window_size,
					max_nonce: None,
					_nonce_type: PhantomData::default(),
				}
			}

			pub fn update(&mut self, nonce: N) -> Result<Option<()>, ReplayedNonce<N>> {
				// already seen
				if !self.nonces.insert(nonce) {
					return Err(ReplayedNonce { nonce });
				}

				// set max nonce
				let max = if let Some(max) = self.max_nonce {
					if nonce > max { nonce } else { max }
				} else {
					nonce
				};

				self.max_nonce = Some(max);

				// determine if in window
				let min = max.saturating_sub(
					FromPrimitive::from_usize(self.minimum_window_size)
						.unwrap_or_else(N::max_value),
				);
				if nonce < min {
					// uncertain
					Ok(None)
				} else {
					// accept
					Ok(Some(()))
				}
			}
		}
	}

	fn check<B: PrimUInt, N: PrimUInt + Hash>(
		model: &mut ModelWindow<B, N>,
		target: &mut SlidingWindow<B, N>,
		nonce: N,
		print: bool,
	) -> bool
	{
		let expected = model.update(nonce);
		let actual = target.update(nonce);

		if let Ok(check) = expected {
			if check.is_some() {
				if print {
					eprint!("Accept");
				}
				actual.is_ok()
			} else {
				// handle uncertain
				if print {
					eprint!("Undefined");
				}
				true
			}
		} else {
			if print {
				eprint!("Reject");
			}
			actual.is_err()
		}
	}

	fn random_increment<B: PrimUInt, N: PrimUInt + Hash + Debug>(
		minimum_window_size: usize,
		max_sub: usize,
		max_add: usize,
		iters: usize,
		print: bool,
	)
	{
		if print {
			eprintln!(
				"Block Type: {:?}, Nonce Type: {:?}, Minimum Window Size: {:?}, Max Sub: {:?}, Max Add: {:?}, Iters: {:?}",
				std::any::type_name::<B>(),
				std::any::type_name::<N>(),
				minimum_window_size,
				max_sub,
				max_add,
				iters
			);
		}

		let model_window = &mut ModelWindow::<B, N>::new(minimum_window_size);
		let window = &mut SlidingWindow::<B, N>::new(minimum_window_size);

		let mut nonce = N::zero();

		let rand_range = &mut Uniform::from(0..max_sub + max_add);
		let rng = &mut rand::thread_rng();

		for _ in 0..iters {
			let diff = (rand_range.sample(rng) as i64) - (max_sub as i64);
			nonce = if diff.is_negative() {
				nonce.saturating_sub(FromPrimitive::from_i64(diff.abs()).unwrap())
			} else {
				nonce.saturating_add(FromPrimitive::from_i64(diff).unwrap())
			};

			if print {
				eprintln!("Nonce: {:?}", nonce);
			}
			assert!(check(model_window, window, nonce, print));
		}

		if print {
			eprintln!();
		}
	}

	#[test]
	fn random_u64_u64() { random_increment::<u64, u64>(16 * 64, 16, 64, 10_000, true); }
}

/// Error returned when calling update(2) on a sliding window and the nonce has already been used
#[derive(Debug)]
pub struct ReplayedNonce<N: PrimUInt> {
	nonce: N,
}

impl<N: PrimUInt + Display + Debug> Error for ReplayedNonce<N> {}

impl<N: PrimUInt + Display> Display for ReplayedNonce<N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "Nonce {} has been replayed", self.nonce)
	}
}

/// Primitive unsigned integers that can be derived from a primitive type
pub trait PrimUInt: Unsigned + PrimInt + FromPrimitive {}

impl<T: Unsigned + PrimInt + FromPrimitive> PrimUInt for T {}

/// Tracks the usage of nonces
pub struct SlidingWindow<B: PrimUInt, N: PrimUInt> {
	window: Box<[B]>,
	wt: usize,
	wb: usize,
	_nonce_type: PhantomData<N>,
}

impl<B: PrimUInt, N: PrimUInt> SlidingWindow<B, N> {
	/// Create a new SlidingWindow to track nonces
	pub fn new(minimum_window_size: usize) -> Self {
		let bits = N::zero().count_zeros() as usize;
		let blocks = ((minimum_window_size + bits - 1) / bits) + 1;

		Self {
			window: vec![B::zero(); blocks].into_boxed_slice(),
			wt: ((blocks - 1) * bits) - 1,
			wb: 0,
			_nonce_type: PhantomData::default(),
		}
	}

	/// Record nonce and detect replay
	///
	/// # Errors
	/// ReplayedNonce returned if the nonce is invalid
	pub fn update(&mut self, nonce: N) -> Result<(), ReplayedNonce<N>> { unimplemented!() }
}
