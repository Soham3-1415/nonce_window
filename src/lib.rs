#![deny(missing_debug_implementations)]

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
	fmt::{self, Binary, Debug, Display, Formatter},
	marker::PhantomData,
};

use num_traits::{FromPrimitive, One, PrimInt, Unsigned, Zero};

#[cfg(test)]
mod tests;

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
	wt: N,
	wb: N,
	log_nonces_per_block: usize,
	log_blocks: usize,
	_nonce_type: PhantomData<N>,
}

impl<B: PrimUInt + Debug + Binary, N: PrimUInt> Debug for SlidingWindow<B, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		// nonce bits
		let nonce_mask = !(N::max_value() << self.log_nonces_per_block);
		// block bits
		let block_mask = !(N::max_value() << self.log_blocks);

		// index in block
		let block_index_wt = B::from(self.wt & nonce_mask).unwrap();
		// index in window
		let block_wt = ((self.wt >> self.log_nonces_per_block) & block_mask)
			.to_usize()
			.unwrap();
		// bitmask to extract bit representing nonce status in a block
		let nonce_bitmap_mask_wt = B::one()
			<< (((B::one() << self.log_nonces_per_block) - block_index_wt)
				.to_usize()
				.unwrap() - 1);

		// index in block
		let block_index_wb = B::from(self.wb & nonce_mask).unwrap();
		// index in window
		let block_wb = ((self.wb >> self.log_nonces_per_block) & block_mask)
			.to_usize()
			.unwrap();
		// bitmask to extract bit representing nonce status in a block
		let nonce_bitmap_mask_wb = B::one()
			<< (((B::one() << self.log_nonces_per_block) - block_index_wb)
				.to_usize()
				.unwrap() - 1);

		let nonces_per_block = usize::one() << self.log_nonces_per_block;
		let mut output = String::with_capacity((nonces_per_block + 1) << self.log_blocks);
		for (block_index, &block) in self.window.iter().enumerate() {
			let tmp = &mut format!("{:0width$b} ", block, width = nonces_per_block).into_bytes();

			if block_index == block_wt {
				tmp[nonce_bitmap_mask_wt.leading_zeros() as usize] =
					if block & nonce_bitmap_mask_wt == B::zero() {
						b't'
					} else {
						b'T'
					};
			}

			if block_index == block_wb {
				tmp[nonce_bitmap_mask_wb.leading_zeros() as usize] =
					if block & nonce_bitmap_mask_wb == B::zero() {
						b'b'
					} else {
						b'B'
					};
			}

			let tmp = tmp.iter().map(|&c| c as char).collect::<String>();
			output.push_str(&tmp);
		}
		write!(f, "{}", output)
	}
}

impl<B: PrimUInt, N: PrimUInt> SlidingWindow<B, N> {
	/// Create a new SlidingWindow to track nonces
	pub fn new(minimum_window_size: usize) -> Self {
		// no loss of precision expected because B should be a power of 2 bits
		let nonces_per_block = B::zero().count_zeros();
		let log_nonces_per_block = nonces_per_block.trailing_zeros() as usize;

		let minimum_window_size = std::cmp::min(
			minimum_window_size,
			N::max_value()
				.to_usize()
				.unwrap_or_else(usize::max_value)
				.saturating_add(1),
		);

		let blocks = {
			// divide and find blocks
			let mut blocks = minimum_window_size >> log_nonces_per_block;
			// account for remainder
			if minimum_window_size > (blocks << log_nonces_per_block) {
				blocks += 1;
			}
			// add empty block
			blocks += 1;

			// next highest power of 2
			let mut shift = 1u16;
			let usize_bits = usize::zero().count_zeros() as u16;
			blocks -= 1;
			while shift < usize_bits {
				blocks |= blocks >> shift;
				shift *= 2;
			}
			blocks += 1;

			blocks
		};
		let log_blocks = blocks.trailing_zeros() as usize;

		let wt =
			N::from_usize(((blocks - 1) << log_nonces_per_block) - 1).unwrap_or_else(N::max_value); // only fail if usize is too large

		assert_eq!(1, blocks.count_ones()); // num blocks is a power of 2
		assert_eq!(1, B::zero().count_zeros().count_ones()); // size of blocks is a power of 2
		assert!((blocks - 1).saturating_mul(nonces_per_block as usize) >= minimum_window_size); // enough blocks
		assert!(log_nonces_per_block <= N::zero().count_zeros() as usize); // no bitshift overflow
		assert!(log_blocks <= N::zero().count_zeros() as usize); // no bitshift overflow

		Self {
			window: vec![B::zero(); blocks].into_boxed_slice(),
			wt,
			wb: N::zero(),
			log_nonces_per_block,
			log_blocks,
			_nonce_type: PhantomData::default(),
		}
	}

	/// Record nonce and detect replay
	///
	/// # Errors
	/// ReplayedNonce returned if the nonce is invalid
	pub fn update(&mut self, nonce: N) -> Result<(), ReplayedNonce<N>> {
		// too small
		if nonce < self.wb {
			return Err(ReplayedNonce { nonce });
		}

		// nonce bits
		let nonce_mask = !(N::max_value() << self.log_nonces_per_block);
		// block bits
		let block_mask = !(N::max_value() << self.log_blocks);

		// index in block
		let block_index = B::from(nonce & nonce_mask).unwrap();
		// index in window
		let block = ((nonce >> self.log_nonces_per_block) & block_mask)
			.to_usize()
			.unwrap();

		// bitmask to extract bit representing nonce status in a block
		let nonce_bitmap_mask = B::one()
			<< (((B::one() << self.log_nonces_per_block) - block_index)
				.to_usize()
				.unwrap() - 1);

		// in range
		if nonce <= self.wt {
			if self.window[block] & nonce_bitmap_mask > B::zero() {
				// already used
				return Err(ReplayedNonce { nonce });
			}

			// mark as used
			self.window[block] = self.window[block] | nonce_bitmap_mask;

			return Ok(());
		}

		let start = self.wb >> self.log_nonces_per_block;

		self.wb = nonce - (self.wt - self.wb);
		self.wt = nonce;

		let end = std::cmp::min(
			self.wb >> self.log_nonces_per_block,
			start.saturating_add(N::one() << self.log_blocks),
		);

		{
			let mut block = start;
			while block < end {
				let index = (block & block_mask).to_usize().unwrap();
				self.window[index] = B::zero();

				block = block + N::one();
			}
		}

		// mark as used
		self.window[block] = self.window[block] | nonce_bitmap_mask;

		Ok(())
	}
}
