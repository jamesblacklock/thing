mod sha256;
use sha256::*;
use std::fmt;

struct Block {
	prev: Sha256,
	n: u64,
	timestamp: u64,
	nonce: u64,
}

impl Block {
	fn as_bytes<'a>(&'a self) -> &'a [u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(self), std::mem::size_of::<Block>()) }
	}
}

impl fmt::Debug for Block {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?}\n{}\n{}\n{}", self.prev, self.n, self.timestamp, self.nonce).unwrap();
		Ok(())
	}
}

fn now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

const MAX_DIFFICULTY_TARGET: u32 = 0x0000ffff;

fn adjust_difficulty_target(prev_target: u32, time_elapsed: u64, block_count: u64) -> u32 {
	assert!(prev_target > 0);
	assert!(block_count > 0);

	let target_time_per_block = 30;
	let target_time_total = (block_count * target_time_per_block) as f64;

	let time_elapsed = if (time_elapsed as f64) < target_time_total/4.0 {
		target_time_total/4.0
	} else if target_time_total*4.0 > time_elapsed as f64 {
		target_time_total*4.0
	} else {
		std::cmp::max(1, time_elapsed) as f64
	};

	let prev_difficulty = f64::max(1.0, MAX_DIFFICULTY_TARGET as f64 / prev_target as f64);
	// println!("{} {} {}", prev_difficulty, time_elapsed, target_time_total);
	let new_difficulty = f64::max(1.0, prev_difficulty * target_time_total / time_elapsed);

	let target = (MAX_DIFFICULTY_TARGET as f64 / new_difficulty) as u32;

	println!("difficulty: {:08x} => {:08x} (avg. time/block: {}. target: {})\n", prev_target, target, time_elapsed as f64 / block_count as f64, target_time_per_block);
	target
}

fn main() {
	let mut candidate = Block {
		prev: Sha256::default(),
		n: 0,
		timestamp: now(),
		nonce: 0,
	};

	let difficulty_period = 10;
	let mut difficulty_target = MAX_DIFFICULTY_TARGET;
	let mut difficulty_period_start = candidate.timestamp;
	let mut difficulty_period_block = candidate.n;

	loop {
		let hash = loop {
			let hash = compute_sha256(candidate.as_bytes());
			if hash.as_words()[0] <= difficulty_target {
				// println!("{:08x}", hash.as_words()[0]);
				break hash;
			} else {
				candidate.nonce += 1;
			}
		};

		println!("{:?}\n{:?}\n", candidate, hash);

		candidate = Block {
			prev: hash,
			n: candidate.n + 1,
			timestamp: now(),
			nonce: 0,
		};

		if candidate.n % difficulty_period == 0 {
			difficulty_target = adjust_difficulty_target(
				difficulty_target, candidate.timestamp - difficulty_period_start, candidate.n - difficulty_period_block);
			difficulty_period_start = candidate.timestamp;
			difficulty_period_block = candidate.n
		}
	}
}