use std::{
	fmt::{Binary, Debug},
	hash::Hash,
};

use num_traits::FromPrimitive;
use rand::{
	distributions::{Distribution, Uniform},
	prelude::StdRng,
	SeedableRng,
};

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
			let max = self
				.max_nonce
				.map(|max| std::cmp::max(nonce, max))
				.unwrap_or(nonce);
			self.max_nonce = Some(max);

			// determine if in window
			let min = max.saturating_sub(
				FromPrimitive::from_usize(self.minimum_window_size).unwrap_or_else(N::max_value),
			);
			if nonce <= min {
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
			let result = actual.is_ok();
			if print || !result {
				eprint!("Accept");
			}
			result
		} else {
			// handle uncertain
			if print {
				eprint!("Undefined");
			}
			true
		}
	} else {
		let result = actual.is_err();
		if print || !result {
			eprint!("Reject");
		}
		result
	}
}

fn random_increment<B: PrimUInt + Debug + Binary, N: PrimUInt + Hash + Debug>(
	minimum_window_size: usize,
	max_sub: usize,
	max_add: usize,
	iters: usize,
	print: bool,
	seed: Option<u64>,
)
{
	if print {
		eprintln!(
			"Block Type: {:?}, Nonce Type: {:?}, Minimum Window Size: {:?}, Max Sub: {:?}, Max Add: {:?}, Iters: {:?}, Seed: {:?}",
			std::any::type_name::<B>(),
			std::any::type_name::<N>(),
			minimum_window_size,
			max_sub,
			max_add,
			iters,
			seed,
		);
	}

	let model_window = &mut ModelWindow::<B, N>::new(minimum_window_size);
	let window = &mut SlidingWindow::<B, N>::new(minimum_window_size);

	let mut nonce = N::zero();

	let rand_range = &mut Uniform::from(0..max_sub + max_add);
	let rng = &mut seed
		.map(StdRng::seed_from_u64)
		.unwrap_or_else(StdRng::from_entropy);

	for _ in 0..iters {
		let diff = (rand_range.sample(rng) as i64) - (max_sub as i64);
		nonce = if diff.is_negative() {
			nonce.saturating_sub(FromPrimitive::from_i64(diff.abs()).unwrap_or_else(N::max_value))
		} else {
			nonce.saturating_add(FromPrimitive::from_i64(diff).unwrap_or_else(N::max_value))
		};

		let result = check(model_window, window, nonce, print);
		if print || !result {
			eprintln!(" {:?}", nonce);
			eprintln!("{:?}", window);
		}
		assert!(result);
	}

	if print {
		eprintln!();
	}
}

fn random<B: PrimUInt + Debug + Binary, N: PrimUInt + Hash + Debug>() {
	let seed = std::env::var("RNG_SEED")
		.map(|seed| Some(seed.parse().unwrap()))
		.unwrap_or_else(|_| None);
	let print = std::env::var("PRINT_OUT")
		.unwrap_or_else(|_| String::from("false"))
		.parse()
		.unwrap();

	#[cfg(debug_assertions)]
	let iters = 10_000;
	#[cfg(not(debug_assertions))]
	let iters = 1_000_000;

	let window_sizes: [usize; 5] = [1, 8, 256, 2048, 8192];
	let max_subs: [usize; 5] = [4, 64, 256, 4096, 100_000];
	let max_adds: [usize; 5] = [4, 64, 256, 4096, 100_000];

	for &window_size in window_sizes.iter() {
		for &max_sub in max_subs.iter() {
			for &max_add in max_adds.iter() {
				random_increment::<B, N>(window_size, max_sub, max_add, iters, print, seed);
			}
		}
	}
}

#[test]
fn random_u8_u8() { random::<u8, u8>(); }

#[test]
fn random_u16_u8() { random::<u16, u8>(); }

#[test]
fn random_u32_u8() { random::<u32, u8>(); }

#[test]
fn random_u64_u8() { random::<u64, u8>(); }

#[test]
fn random_u128_u8() { random::<u128, u8>(); }

#[test]
fn random_usize_u8() { random::<usize, u8>(); }

#[test]
fn random_u8_u16() { random::<u8, u16>(); }

#[test]
fn random_u16_u16() { random::<u16, u16>(); }

#[test]
fn random_u32_u16() { random::<u32, u16>(); }

#[test]
fn random_u64_u16() { random::<u64, u16>(); }

#[test]
fn random_u128_u16() { random::<u128, u16>(); }

#[test]
fn random_usize_u16() { random::<usize, u16>(); }

#[test]
fn random_u8_u32() { random::<u8, u32>(); }

#[test]
fn random_u16_u32() { random::<u16, u32>(); }

#[test]
fn random_u32_u32() { random::<u32, u32>(); }

#[test]
fn random_u64_u32() { random::<u64, u32>(); }

#[test]
fn random_u128_u32() { random::<u128, u32>(); }

#[test]
fn random_usize_u32() { random::<usize, u32>(); }

#[test]
fn random_u8_u64() { random::<u8, u64>(); }

#[test]
fn random_u16_u64() { random::<u16, u64>(); }

#[test]
fn random_u32_u64() { random::<u32, u64>(); }

#[test]
fn random_u64_u64() { random::<u64, u64>(); }

#[test]
fn random_u128_u64() { random::<u128, u64>(); }

#[test]
fn random_usize_u64() { random::<usize, u64>(); }

#[test]
fn random_u8_u128() { random::<u8, u128>(); }

#[test]
fn random_u16_u128() { random::<u16, u128>(); }

#[test]
fn random_u32_u128() { random::<u32, u128>(); }

#[test]
fn random_u64_u128() { random::<u64, u128>(); }

#[test]
fn random_u128_u128() { random::<u128, u128>(); }

#[test]
fn random_usize_u128() { random::<usize, u128>(); }

#[test]
fn random_u8_usize() { random::<u8, usize>(); }

#[test]
fn random_u16_usize() { random::<u16, usize>(); }

#[test]
fn random_u32_usize() { random::<u32, usize>(); }

#[test]
fn random_u64_usize() { random::<u64, usize>(); }

#[test]
fn random_u128_usize() { random::<u128, usize>(); }

#[test]
fn random_usize_usize() { random::<usize, usize>(); }

#[test]
fn print_sliding_window_test_debug() {
	random_increment::<u64, u64>(512, 64, 128, 128, true, None);
}

#[test]
fn print_replayed_nonce() {
	let window = &mut SlidingWindow::<u64, u64>::new(512);

	window.update(1).unwrap();
	println!("{:?}", window.update(1).unwrap_err());
	println!("{}", window.update(1).unwrap_err());
}
