# Nonce Window
[![Build Status](https://travis-ci.com/Soham3-1415/nonce_window.svg?token=m1JaVhcrW1uB3xwn43d2&branch=master)](https://travis-ci.com/Soham3-1415/nonce_window)
[![codecov](https://codecov.io/gh/Soham3-1415/nonce_window/branch/master/graph/badge.svg?token=3HOSHEBYSV)](https://codecov.io/gh/Soham3-1415/nonce_window)

Implementation of Anti-Replay Algorithm without Bit Shifting based on RFC 6479.
Number of blocks is not necessarily a power of two.

# Examples
``` rust
use nonce_window::SlidingWindow;

let mut window = SlidingWindow::<u64, u64>::new(64);

assert_eq!((), window.update(5).unwrap());
window.update(5).unwrap_err(); // reuse

assert_eq!((), window.update(20).unwrap());
assert_eq!((), window.update(4).unwrap());
window.update(4).unwrap_err(); // reuse

assert_eq!((), window.update(128).unwrap()); // advance window
let _unused_result = window.update(10); // may or may not return an error
window.update(10).unwrap_err(); // reuse
```

- A nonce will be accepted
if it is not less than the highest accepted nonce minus minimum_sliding_window_size
AND it has not been accepted before
- A nonce will be rejected if it has been accepted before
- A nonce that has not been accepted before
AND is less than the highest accepted nonce minus minimum_sliding_window_size
MAY be rejected
