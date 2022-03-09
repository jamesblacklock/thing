// rol(x, n) cyclically rotates x over n bits to the left
fn rol(x: u32, n: u32) -> u32 {
	assert!(0 <= n && n < 32);
	(x << n) | (x >> (32 - n))
}

fn f(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }
fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
fn h(x: u32, y: u32, z: u32) -> u32 { (x | !y) ^ z }
fn i(x: u32, y: u32, z: u32) -> u32 { (x & z) | (y & !z) }
fn j(x: u32, y: u32, z: u32) -> u32 { x ^ (y | !z) }

// the ten basic operations ff() through iii()
fn ff(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += f(b, c, d) + x;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn gg(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += g(b, c, d) + x + 0x5a827999;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn hh(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += h(b, c, d) + x + 0x6ed9eba1;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn ii(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += i(b, c, d) + x + 0x8f1bbcdc;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn jj(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += j(b, c, d) + x + 0xa953fd4e;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn fff(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += f(b, c, d) + x;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn ggg(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += g(b, c, d) + x + 0x7a6d76e9;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn hhh(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += h(b, c, d) + x + 0x6d703ef3;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn iii(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += i(b, c, d) + x + 0x5c4dd124;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}
fn jjj(mut a: u32, b: u32, mut c: u32, d: u32, e: u32, x: u32, s: u32) -> (u32, u32) {
	a += j(b, c, d) + x + 0x50a28be6;
	a = rol(a, s) + e;
	c = rol(c, 10);
	(a, c)
}

unsafe fn bytes_to_dword(bytes: &[u8], i: usize) -> u32 {
	let cast: &[u32] = std::slice::from_raw_parts(std::mem::transmute(&bytes[0]), usize::MAX);
	u32::from_le_bytes(cast[i].to_ne_bytes())
}

const T: [[u32; 4]; 3] = [
	[0x6a08c71c, 0x22fa6a04, 0x8fe83a35, 0xebac3d3d],
	[0x7102fae3, 0x851d490e, 0x34cc5111, 0x418d71e4],
	[0x57759893, 0x02817bc0, 0x492959ba, 0x378f63eb],
];

// calculates T0, T1, T2 required for ripemd160
// this only needs to be done once
fn mdmac_const_t() -> [[u32; 4]; 3] {
	let mut t: [[u32; 4]; 3] = [[0; 4]; 3];

	let mut mdbuf = [0; 5];
	let mut u = "00abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		.as_bytes().iter().copied().collect::<Vec<_>>();
	let k: [u32; 9] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0, 0, 0, 0];
	let mut x: [u32; 16] = [0; 16];

	for i in 0..3usize {
		u[0] = 0x30 + i as u8;
		u[1] = u[0];
		mdmac_init(&k, &mut mdbuf);
		for j in 0..16 {
			x[j] = unsafe { bytes_to_dword(u.as_slice(), j) };
		}
		compress(&k, &mut mdbuf, &x);
		t[i][0] = mdbuf[0];
		t[i][1] = mdbuf[1];
		t[i][2] = mdbuf[2];
		t[i][3] = mdbuf[3];
	}

	return t
}

// expands 128-bit key into (5+4+4)*32-bit K required for ripemd160
fn mdmac_setup(key: [u8; 16]) -> [u32; 14] {
	let t = mdmac_const_t();
	let mut u = [0; 16];
	let kk = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0, 0, 0, 0];
	let mut k = [0; 14];

	mdmac_init(&kk, &mut k[0..5]);
	for i in 0..4 {
	  u[i]    = unsafe { bytes_to_dword(&key, i) };
	  u[i+4]  = t[0][i];
	  u[i+8]  = t[1][i];
	  u[i+12] = t[2][i];
	}
	compress(&kk, &mut k[0..5], &u);
	for i in 0..4 {
	  u[i]    = t[0][i];
	  u[i+4]  = t[1][i];
	  u[i+8]  = t[2][i];
	  u[i+12] = unsafe { bytes_to_dword(&key, i) };
	}
	compress(&kk, &mut k[0..5], &u);

	mdmac_init(&kk, &mut k[5..10]);
	for i in 0..4 {
	  u[i]    = unsafe { bytes_to_dword(&key, i) };
	  u[i+4]  = t[1][i];
	  u[i+8]  = t[2][i];
	  u[i+12] = t[0][i];
	}
	compress(&kk, &mut k[5..10], &u);
	for i in 0..4 {
	  u[i]    = t[1][i];
	  u[i+4]  = t[2][i];
	  u[i+8]  = t[0][i];
	  u[i+12] = unsafe { bytes_to_dword(&key, i) };
	}
	compress(&kk, &mut k[5..10], &u);

	mdmac_init(&kk, &mut k[9..14]);
	for i in 0..4 {
	  u[i]    = unsafe { bytes_to_dword(&key, i) };
	  u[i+4]  = t[2][i];
	  u[i+8]  = t[0][i];
	  u[i+12] = t[1][i];
	}
	compress(&kk, &mut k[9..14], &u);
	for i in 0..4 {
	  u[i]    = t[2][i];
	  u[i+4]  = t[0][i];
	  u[i+8]  = t[1][i];
	  u[i+12] = unsafe { bytes_to_dword(&key, i) };
	}
	compress(&kk, &mut k[9..14], &u);

	return k;
}

fn mdmac_init(k: &[u32; 9], mdbuf: &mut [u32]) {
	mdbuf[0] = k[0];
	mdbuf[1] = k[1];
	mdbuf[2] = k[2];
	mdbuf[3] = k[3];
	mdbuf[4] = k[4];
}

fn compress(k: &[u32; 9], mdbuf: &mut [u32], x: &[u32; 16]) {
	let mut aa = mdbuf[0];
	let mut bb = mdbuf[1];
	let mut cc = mdbuf[2];
	let mut dd = mdbuf[3];
	let mut ee = mdbuf[4];
	let mut aaa = mdbuf[0];
	let mut bbb = mdbuf[1];
	let mut ccc = mdbuf[2];
	let mut ddd = mdbuf[3];
	let mut eee = mdbuf[4];

	// round 1
	(aa, cc) = ff(aa, bb, cc, dd, ee, x[ 0]+k[5], 11);
	(ee, bb) = ff(ee, aa, bb, cc, dd, x[ 1]+k[5], 14);
	(dd, aa) = ff(dd, ee, aa, bb, cc, x[ 2]+k[5], 15);
	(cc, ee) = ff(cc, dd, ee, aa, bb, x[ 3]+k[5], 12);
	(bb, dd) = ff(bb, cc, dd, ee, aa, x[ 4]+k[5],  5);
	(aa, cc) = ff(aa, bb, cc, dd, ee, x[ 5]+k[5],  8);
	(ee, bb) = ff(ee, aa, bb, cc, dd, x[ 6]+k[5],  7);
	(dd, aa) = ff(dd, ee, aa, bb, cc, x[ 7]+k[5],  9);
	(cc, ee) = ff(cc, dd, ee, aa, bb, x[ 8]+k[5], 11);
	(bb, dd) = ff(bb, cc, dd, ee, aa, x[ 9]+k[5], 13);
	(aa, cc) = ff(aa, bb, cc, dd, ee, x[10]+k[5], 14);
	(ee, bb) = ff(ee, aa, bb, cc, dd, x[11]+k[5], 15);
	(dd, aa) = ff(dd, ee, aa, bb, cc, x[12]+k[5],  6);
	(cc, ee) = ff(cc, dd, ee, aa, bb, x[13]+k[5],  7);
	(bb, dd) = ff(bb, cc, dd, ee, aa, x[14]+k[5],  9);
	(aa, cc) = ff(aa, bb, cc, dd, ee, x[15]+k[5],  8);
								
	// round 2
	(ee, bb) = gg(ee, aa, bb, cc, dd, x[ 7]+k[6],  7);
	(dd, aa) = gg(dd, ee, aa, bb, cc, x[ 4]+k[6],  6);
	(cc, ee) = gg(cc, dd, ee, aa, bb, x[13]+k[6],  8);
	(bb, dd) = gg(bb, cc, dd, ee, aa, x[ 1]+k[6], 13);
	(aa, cc) = gg(aa, bb, cc, dd, ee, x[10]+k[6], 11);
	(ee, bb) = gg(ee, aa, bb, cc, dd, x[ 6]+k[6],  9);
	(dd, aa) = gg(dd, ee, aa, bb, cc, x[15]+k[6],  7);
	(cc, ee) = gg(cc, dd, ee, aa, bb, x[ 3]+k[6], 15);
	(bb, dd) = gg(bb, cc, dd, ee, aa, x[12]+k[6],  7);
	(aa, cc) = gg(aa, bb, cc, dd, ee, x[ 0]+k[6], 12);
	(ee, bb) = gg(ee, aa, bb, cc, dd, x[ 9]+k[6], 15);
	(dd, aa) = gg(dd, ee, aa, bb, cc, x[ 5]+k[6],  9);
	(cc, ee) = gg(cc, dd, ee, aa, bb, x[ 2]+k[6], 11);
	(bb, dd) = gg(bb, cc, dd, ee, aa, x[14]+k[6],  7);
	(aa, cc) = gg(aa, bb, cc, dd, ee, x[11]+k[6], 13);
	(ee, bb) = gg(ee, aa, bb, cc, dd, x[ 8]+k[6], 12);

	// round 3
	(dd, aa) = hh(dd, ee, aa, bb, cc, x[ 3]+k[7], 11);
	(cc, ee) = hh(cc, dd, ee, aa, bb, x[10]+k[7], 13);
	(bb, dd) = hh(bb, cc, dd, ee, aa, x[14]+k[7],  6);
	(aa, cc) = hh(aa, bb, cc, dd, ee, x[ 4]+k[7],  7);
	(ee, bb) = hh(ee, aa, bb, cc, dd, x[ 9]+k[7], 14);
	(dd, aa) = hh(dd, ee, aa, bb, cc, x[15]+k[7],  9);
	(cc, ee) = hh(cc, dd, ee, aa, bb, x[ 8]+k[7], 13);
	(bb, dd) = hh(bb, cc, dd, ee, aa, x[ 1]+k[7], 15);
	(aa, cc) = hh(aa, bb, cc, dd, ee, x[ 2]+k[7], 14);
	(ee, bb) = hh(ee, aa, bb, cc, dd, x[ 7]+k[7],  8);
	(dd, aa) = hh(dd, ee, aa, bb, cc, x[ 0]+k[7], 13);
	(cc, ee) = hh(cc, dd, ee, aa, bb, x[ 6]+k[7],  6);
	(bb, dd) = hh(bb, cc, dd, ee, aa, x[13]+k[7],  5);
	(aa, cc) = hh(aa, bb, cc, dd, ee, x[11]+k[7], 12);
	(ee, bb) = hh(ee, aa, bb, cc, dd, x[ 5]+k[7],  7);
	(dd, aa) = hh(dd, ee, aa, bb, cc, x[12]+k[7],  5);

	// round 4
	(cc, ee) = ii(cc, dd, ee, aa, bb, x[ 1]+k[8], 11);
	(bb, dd) = ii(bb, cc, dd, ee, aa, x[ 9]+k[8], 12);
	(aa, cc) = ii(aa, bb, cc, dd, ee, x[11]+k[8], 14);
	(ee, bb) = ii(ee, aa, bb, cc, dd, x[10]+k[8], 15);
	(dd, aa) = ii(dd, ee, aa, bb, cc, x[ 0]+k[8], 14);
	(cc, ee) = ii(cc, dd, ee, aa, bb, x[ 8]+k[8], 15);
	(bb, dd) = ii(bb, cc, dd, ee, aa, x[12]+k[8],  9);
	(aa, cc) = ii(aa, bb, cc, dd, ee, x[ 4]+k[8],  8);
	(ee, bb) = ii(ee, aa, bb, cc, dd, x[13]+k[8],  9);
	(dd, aa) = ii(dd, ee, aa, bb, cc, x[ 3]+k[8], 14);
	(cc, ee) = ii(cc, dd, ee, aa, bb, x[ 7]+k[8],  5);
	(bb, dd) = ii(bb, cc, dd, ee, aa, x[15]+k[8],  6);
	(aa, cc) = ii(aa, bb, cc, dd, ee, x[14]+k[8],  8);
	(ee, bb) = ii(ee, aa, bb, cc, dd, x[ 5]+k[8],  6);
	(dd, aa) = ii(dd, ee, aa, bb, cc, x[ 6]+k[8],  5);
	(cc, ee) = ii(cc, dd, ee, aa, bb, x[ 2]+k[8], 12);

	// round 5
	(bb, dd) = jj(bb, cc, dd, ee, aa, x[ 4]+k[5],  9);
	(aa, cc) = jj(aa, bb, cc, dd, ee, x[ 0]+k[5], 15);
	(ee, bb) = jj(ee, aa, bb, cc, dd, x[ 5]+k[5],  5);
	(dd, aa) = jj(dd, ee, aa, bb, cc, x[ 9]+k[5], 11);
	(cc, ee) = jj(cc, dd, ee, aa, bb, x[ 7]+k[5],  6);
	(bb, dd) = jj(bb, cc, dd, ee, aa, x[12]+k[5],  8);
	(aa, cc) = jj(aa, bb, cc, dd, ee, x[ 2]+k[5], 13);
	(ee, bb) = jj(ee, aa, bb, cc, dd, x[10]+k[5], 12);
	(dd, aa) = jj(dd, ee, aa, bb, cc, x[14]+k[5],  5);
	(cc, ee) = jj(cc, dd, ee, aa, bb, x[ 1]+k[5], 12);
	(bb, dd) = jj(bb, cc, dd, ee, aa, x[ 3]+k[5], 13);
	(aa, cc) = jj(aa, bb, cc, dd, ee, x[ 8]+k[5], 14);
	(ee, bb) = jj(ee, aa, bb, cc, dd, x[11]+k[5], 11);
	(dd, aa) = jj(dd, ee, aa, bb, cc, x[ 6]+k[5],  8);
	(cc, ee) = jj(cc, dd, ee, aa, bb, x[15]+k[5],  5);
	(bb, dd) = jj(bb, cc, dd, ee, aa, x[13]+k[5],  6);

	// parallel round 1
	(aaa, ccc) = jjj(aaa, bbb, ccc, ddd, eee, x[ 5]+k[6],  8);
	(eee, bbb) = jjj(eee, aaa, bbb, ccc, ddd, x[14]+k[6],  9);
	(ddd, aaa) = jjj(ddd, eee, aaa, bbb, ccc, x[ 7]+k[6],  9);
	(ccc, eee) = jjj(ccc, ddd, eee, aaa, bbb, x[ 0]+k[6], 11);
	(bbb, ddd) = jjj(bbb, ccc, ddd, eee, aaa, x[ 9]+k[6], 13);
	(aaa, ccc) = jjj(aaa, bbb, ccc, ddd, eee, x[ 2]+k[6], 15);
	(eee, bbb) = jjj(eee, aaa, bbb, ccc, ddd, x[11]+k[6], 15);
	(ddd, aaa) = jjj(ddd, eee, aaa, bbb, ccc, x[ 4]+k[6],  5);
	(ccc, eee) = jjj(ccc, ddd, eee, aaa, bbb, x[13]+k[6],  7);
	(bbb, ddd) = jjj(bbb, ccc, ddd, eee, aaa, x[ 6]+k[6],  7);
	(aaa, ccc) = jjj(aaa, bbb, ccc, ddd, eee, x[15]+k[6],  8);
	(eee, bbb) = jjj(eee, aaa, bbb, ccc, ddd, x[ 8]+k[6], 11);
	(ddd, aaa) = jjj(ddd, eee, aaa, bbb, ccc, x[ 1]+k[6], 14);
	(ccc, eee) = jjj(ccc, ddd, eee, aaa, bbb, x[10]+k[6], 14);
	(bbb, ddd) = jjj(bbb, ccc, ddd, eee, aaa, x[ 3]+k[6], 12);
	(aaa, ccc) = jjj(aaa, bbb, ccc, ddd, eee, x[12]+k[6],  6);

	// parallel round 2
	(eee, bbb) = iii(eee, aaa, bbb, ccc, ddd, x[ 6]+k[7],  9); 
	(ddd, aaa) = iii(ddd, eee, aaa, bbb, ccc, x[11]+k[7], 13);
	(ccc, eee) = iii(ccc, ddd, eee, aaa, bbb, x[ 3]+k[7], 15);
	(bbb, ddd) = iii(bbb, ccc, ddd, eee, aaa, x[ 7]+k[7],  7);
	(aaa, ccc) = iii(aaa, bbb, ccc, ddd, eee, x[ 0]+k[7], 12);
	(eee, bbb) = iii(eee, aaa, bbb, ccc, ddd, x[13]+k[7],  8);
	(ddd, aaa) = iii(ddd, eee, aaa, bbb, ccc, x[ 5]+k[7],  9);
	(ccc, eee) = iii(ccc, ddd, eee, aaa, bbb, x[10]+k[7], 11);
	(bbb, ddd) = iii(bbb, ccc, ddd, eee, aaa, x[14]+k[7],  7);
	(aaa, ccc) = iii(aaa, bbb, ccc, ddd, eee, x[15]+k[7],  7);
	(eee, bbb) = iii(eee, aaa, bbb, ccc, ddd, x[ 8]+k[7], 12);
	(ddd, aaa) = iii(ddd, eee, aaa, bbb, ccc, x[12]+k[7],  7);
	(ccc, eee) = iii(ccc, ddd, eee, aaa, bbb, x[ 4]+k[7],  6);
	(bbb, ddd) = iii(bbb, ccc, ddd, eee, aaa, x[ 9]+k[7], 15);
	(aaa, ccc) = iii(aaa, bbb, ccc, ddd, eee, x[ 1]+k[7], 13);
	(eee, bbb) = iii(eee, aaa, bbb, ccc, ddd, x[ 2]+k[7], 11);

	// parallel round 3
	(ddd, aaa) = hhh(ddd, eee, aaa, bbb, ccc, x[15]+k[8],  9);
	(ccc, eee) = hhh(ccc, ddd, eee, aaa, bbb, x[ 5]+k[8],  7);
	(bbb, ddd) = hhh(bbb, ccc, ddd, eee, aaa, x[ 1]+k[8], 15);
	(aaa, ccc) = hhh(aaa, bbb, ccc, ddd, eee, x[ 3]+k[8], 11);
	(eee, bbb) = hhh(eee, aaa, bbb, ccc, ddd, x[ 7]+k[8],  8);
	(ddd, aaa) = hhh(ddd, eee, aaa, bbb, ccc, x[14]+k[8],  6);
	(ccc, eee) = hhh(ccc, ddd, eee, aaa, bbb, x[ 6]+k[8],  6);
	(bbb, ddd) = hhh(bbb, ccc, ddd, eee, aaa, x[ 9]+k[8], 14);
	(aaa, ccc) = hhh(aaa, bbb, ccc, ddd, eee, x[11]+k[8], 12);
	(eee, bbb) = hhh(eee, aaa, bbb, ccc, ddd, x[ 8]+k[8], 13);
	(ddd, aaa) = hhh(ddd, eee, aaa, bbb, ccc, x[12]+k[8],  5);
	(ccc, eee) = hhh(ccc, ddd, eee, aaa, bbb, x[ 2]+k[8], 14);
	(bbb, ddd) = hhh(bbb, ccc, ddd, eee, aaa, x[10]+k[8], 13);
	(aaa, ccc) = hhh(aaa, bbb, ccc, ddd, eee, x[ 0]+k[8], 13);
	(eee, bbb) = hhh(eee, aaa, bbb, ccc, ddd, x[ 4]+k[8],  7);
	(ddd, aaa) = hhh(ddd, eee, aaa, bbb, ccc, x[13]+k[8],  5);

	// parallel round 4
	(ccc, eee) = ggg(ccc, ddd, eee, aaa, bbb, x[ 8]+k[5], 15);
	(bbb, ddd) = ggg(bbb, ccc, ddd, eee, aaa, x[ 6]+k[5],  5);
	(aaa, ccc) = ggg(aaa, bbb, ccc, ddd, eee, x[ 4]+k[5],  8);
	(eee, bbb) = ggg(eee, aaa, bbb, ccc, ddd, x[ 1]+k[5], 11);
	(ddd, aaa) = ggg(ddd, eee, aaa, bbb, ccc, x[ 3]+k[5], 14);
	(ccc, eee) = ggg(ccc, ddd, eee, aaa, bbb, x[11]+k[5], 14);
	(bbb, ddd) = ggg(bbb, ccc, ddd, eee, aaa, x[15]+k[5],  6);
	(aaa, ccc) = ggg(aaa, bbb, ccc, ddd, eee, x[ 0]+k[5], 14);
	(eee, bbb) = ggg(eee, aaa, bbb, ccc, ddd, x[ 5]+k[5],  6);
	(ddd, aaa) = ggg(ddd, eee, aaa, bbb, ccc, x[12]+k[5],  9);
	(ccc, eee) = ggg(ccc, ddd, eee, aaa, bbb, x[ 2]+k[5], 12);
	(bbb, ddd) = ggg(bbb, ccc, ddd, eee, aaa, x[13]+k[5],  9);
	(aaa, ccc) = ggg(aaa, bbb, ccc, ddd, eee, x[ 9]+k[5], 12);
	(eee, bbb) = ggg(eee, aaa, bbb, ccc, ddd, x[ 7]+k[5],  5);
	(ddd, aaa) = ggg(ddd, eee, aaa, bbb, ccc, x[10]+k[5], 15);
	(ccc, eee) = ggg(ccc, ddd, eee, aaa, bbb, x[14]+k[5],  8);

	// parallel round 5
	(bbb, ddd) = fff(bbb, ccc, ddd, eee, aaa, x[12]+k[6],  8);
	(aaa, ccc) = fff(aaa, bbb, ccc, ddd, eee, x[15]+k[6],  5);
	(eee, bbb) = fff(eee, aaa, bbb, ccc, ddd, x[10]+k[6], 12);
	(ddd, aaa) = fff(ddd, eee, aaa, bbb, ccc, x[ 4]+k[6],  9);
	(ccc, eee) = fff(ccc, ddd, eee, aaa, bbb, x[ 1]+k[6], 12);
	(bbb, ddd) = fff(bbb, ccc, ddd, eee, aaa, x[ 5]+k[6],  5);
	(aaa, ccc) = fff(aaa, bbb, ccc, ddd, eee, x[ 8]+k[6], 14);
	(eee, bbb) = fff(eee, aaa, bbb, ccc, ddd, x[ 7]+k[6],  6);
	(ddd, aaa) = fff(ddd, eee, aaa, bbb, ccc, x[ 6]+k[6],  8);
	(ccc, eee) = fff(ccc, ddd, eee, aaa, bbb, x[ 2]+k[6], 13);
	(bbb, ddd) = fff(bbb, ccc, ddd, eee, aaa, x[13]+k[6],  6);
	(aaa, ccc) = fff(aaa, bbb, ccc, ddd, eee, x[14]+k[6],  5);
	(eee, bbb) = fff(eee, aaa, bbb, ccc, ddd, x[ 0]+k[6], 15);
	(ddd, aaa) = fff(ddd, eee, aaa, bbb, ccc, x[ 3]+k[6], 13);
	(ccc, eee) = fff(ccc, ddd, eee, aaa, bbb, x[ 9]+k[6], 11);
	(bbb, ddd) = fff(bbb, ccc, ddd, eee, aaa, x[11]+k[6], 11);

	// combine results
	ddd += cc + mdbuf[1]; // final result for mdbuf[0]
	mdbuf[1] = mdbuf[2] + dd + eee;
	mdbuf[2] = mdbuf[3] + ee + aaa;
	mdbuf[3] = mdbuf[4] + aa + bbb;
	mdbuf[4] = mdbuf[0] + bb + ccc;
	mdbuf[0] = ddd;
}

fn mdmac_finish(k: &[u32; 9], mdbuf: &mut [u32], strptr: &[u8], lswlen: usize, mswlen: usize) {
	let mut x = [0; 16];

	// put bytes from strptr into X
	for (i, b) in strptr.iter().copied().take(lswlen & 0x3f).enumerate() {
	   // byte i goes into word X[i div 4] at index 8*(i mod 4)
	   x[i>>2] ^= (b as u32) << (8 * (i & 0x3));
	}

	// append the bit m_n == 1
	x[(lswlen >> 2) & 0xf] ^= 1 << (8*(lswlen&3) + 7);

	if (lswlen & 63) > 55 {
	   // length goes to next block
	   compress(&k, mdbuf, &x);
	   x = [0; 16];
	}

	// append length in bits
	x[14] = (lswlen << 3) as u32;
	x[15] = ((lswlen >> 29) | (mswlen << 3)) as u32;
	compress(&k, mdbuf, &x);

	// last block
	for i in 0..4 {
	   x[i]    = k[9+i];
	   x[i+4]  = k[9+i] ^ T[0][i];
	   x[i+8]  = k[9+i] ^ T[1][i];
	   x[i+12] = k[9+i] ^ T[2][i];
	}
	compress(&k, mdbuf, &x);
}

#[test]
fn generate_t() {
	let t = mdmac_const_t();
	assert!(t == T);
}
