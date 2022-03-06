use std::io::Read;
use crate::{
	network::Deserialize,
	err::*,
	common::*,
	json::*,
};

use super::big_int::*;
use super::sha256::Sha256;

// secp256k1​
// fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
pub const ECDSA_PRIME: u256 = u256::from_raw_le([0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
// fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
pub const ECDSA_ORDER: u256 = u256::from_raw_le([0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff]);
pub const ECDSA_A:     u256 = u256::from_raw_le([0, 0, 0, 0]);
pub const ECDSA_B:     u256 = u256::from_raw_le([7, 0, 0, 0]);
pub const ECDSA_BASE: ECDSAPoint = ECDSAPoint::Coord {
	x: u256::from_raw_le([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
	y: u256::from_raw_le([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ECDSAPoint {
	Coord { x: u256, y: u256 },
	Infinity,
}

impl ECDSAPoint {
	pub fn x(&self) -> Option<u256> {
		match self {
			&ECDSAPoint::Infinity => None,
			&ECDSAPoint::Coord { x, y: _ } => Some(x)
		} 
	}

	pub fn y(&self) -> Option<u256> {
		match self {
			&ECDSAPoint::Infinity => None,
			&ECDSAPoint::Coord { x: _, y } => Some(y)
		} 
	}

	pub fn tangent(&self, a: u256, p: u256) -> u256 {
		match self {
			ECDSAPoint::Infinity       => panic!("point at infinity has no tangent"),
			&ECDSAPoint::Coord { x, y } => {
				// s = 3x² + a / 2y
				let numerator = x.mul_mod(x, p).mul_mod(3.into(), p).add_mod(a, p);
				let denominator = y.mul_mod(2.into(), p);
				numerator.mul_mod(denominator.mod_inv(p), p)
			}
		}
	}

	fn double(&self, a: u256, p: u256) -> ECDSAPoint {
		match self {
			ECDSAPoint::Infinity       => self.clone(),
			&ECDSAPoint::Coord { x, y } => {
				let tangent = self.tangent(a, p);
				let new_x = tangent.mul_mod(tangent, p).sub_mod(x, p).sub_mod(x, p);
				let new_y = tangent.mul_mod(x.sub_mod(new_x, p), p).sub_mod(y, p);
				ECDSAPoint::Coord {
					x: new_x,
					y: new_y,
				}
			}
		}
	}

	fn add(&self, other: &ECDSAPoint, a: u256, p: u256) -> ECDSAPoint {
		match (self, other) {
			(ECDSAPoint::Infinity, _) => other.clone(),
			(_, ECDSAPoint::Infinity) => self.clone(),
			(&ECDSAPoint::Coord { x: px, y: py }, &ECDSAPoint::Coord { x: qx, y: qy }) => {
				if (px, py) == (qx, qy) {
					self.double(a, p)
				} else {
					let prime = p;
					let slope = py.sub_mod(qy, prime).mul_mod(px.sub_mod(qx, prime).mod_inv(prime), prime);
					let new_x = slope.mul_mod(slope, prime).sub_mod(px, prime).sub_mod(qx, prime);
					let new_y = slope.mul_mod(px.sub_mod(new_x, prime), prime).sub_mod(py, prime);
					ECDSAPoint::Coord {
						x: new_x.resize(),
						y: new_y.resize(),
					}
				}
			},
		}
	}

	fn mul(&self, scalar: u256, a: u256, p: u256) -> ECDSAPoint {
		match self {
			&ECDSAPoint::Infinity => unimplemented!(),
			&ECDSAPoint::Coord {..} => {
				if scalar == 0.into() {
					unimplemented!();
				}
				let mut powers = vec![(self.clone(), u256::from(1))];
				let mut acc = self.clone();
				let mut count = u256::from(1);
				let mut next_count = count + count;
				while next_count > count && next_count < scalar {
					count = next_count;
					acc = acc.double(a, p);
					powers.push((acc.clone(), count));
					next_count = count + count;
				}
				let (mut n, mut power) = powers.pop().unwrap();
				while count < scalar {
					next_count = count + power;
					if next_count > count && next_count <= scalar {
						acc = acc.add(&n, a, p);
						count = next_count;
					} else if powers.len() == 0 {
						break;
					} else {
						(n, power) = powers.pop().unwrap();
					}
				}
				acc
			},
		}
	}
}

impl std::ops::Mul<ECDSAPoint> for u256 {
	type Output = ECDSAPoint;
	fn mul(self, point: ECDSAPoint) -> ECDSAPoint {
		ECDSAPoint::mul(&point, self, ECDSA_A, ECDSA_PRIME)
	}
}

impl std::ops::Add for ECDSAPoint {
	type Output = ECDSAPoint;
	fn add(self, other: ECDSAPoint) -> ECDSAPoint {
		Self::add(&self, &other, ECDSA_A, ECDSA_PRIME)
	}
}

impl ToJson for ECDSAPoint {
	fn to_json(&self) -> JsonValue {
		match self {
			ECDSAPoint::Coord {x, y} => JsonValue::object([
				("x", JsonValue::string(format!("{}", x))),
				("y", JsonValue::string(format!("{}", y))),
			]),
			ECDSAPoint::Infinity => JsonValue::string("Infinity"),
		}
	}
}

#[derive(Debug)]
pub struct ECDSAPubKey {
	x: u256,
	y: u256,
}

impl ECDSAPubKey {
	pub fn from_coords(x: u256, y: u256) -> Self {
		ECDSAPubKey { x, y }
	}
	
	fn to_point(&self) -> ECDSAPoint {
		ECDSAPoint::Coord { x: self.x, y: self.y }
	}

	#[must_use]
	pub fn verify(&self, sig: &ECDSASig, hash: &Sha256) -> bool {
		// adapted from https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py (public domain)
		let hash = hash.to_u256();
		let g = ECDSA_BASE;
		let n = ECDSA_ORDER;
		let r = sig.r;
		let s = sig.s;
		if r < 1.into() || r > n - 1.into() {
			return false;
		} else if s < 1.into() || s > n - 1.into() {
			return false;
		}
		let c = s.mod_inv(n);
		let u1 = hash.mul_mod(c, n);
		let u2 = r.mul_mod(c, n);
		let point = u1 * g + u2 * self.to_point();
		if let ECDSAPoint::Coord { x, .. } = point {
			let v = x % ECDSA_ORDER;
			v == r
		} else {
			false
		}
	}
}

impl std::convert::TryFrom<&str> for ECDSAPubKey {
	type Error = Err;
	fn try_from(s: &str) -> Result<ECDSAPubKey> {
		ECDSAPubKey::deserialize(&mut &*hex_to_bytes(s)?)
	}
}

impl ToJson for ECDSAPubKey {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("x", JsonValue::string(format!("{}", self.x))),
			("y", JsonValue::string(format!("{}", self.y))),
		])
	}
}

impl Deserialize for ECDSAPubKey {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let mut x = [0; 32];
		let mut y = [0; 32];
		
		let header = read_u8(stream)?;
		read_buf_exact(stream, &mut x)?;
		let temp = x.iter().copied().rev().collect::<Vec<_>>();
		x.copy_from_slice(&temp);

		let y_is_odd = match header {
			0x04 => {
				read_buf_exact(stream, &mut y)?;
				let temp = y.iter().copied().rev().collect::<Vec<_>>();
				y.copy_from_slice(&temp);

				return Ok(ECDSAPubKey {
					x: x.into(),
					y: y.into(),
				})
			},
			0x03 => true,
			0x02 => false,
			_ => return Err(Err::ValueError("invalid pubkey".to_owned()))
		};

		let x = u256::from(x);
		let p = ECDSA_PRIME;

		// y² = x³ + 7 mod p
		let y2 = x.pow_mod(3.into(), p).add_mod(7.into(), p);

		// from an online source: "Secp256k1 is chosen in a special way so that the square root of y² is y²^((p+1)/4)"
		// (p+1)/4 = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
		let exp = u256::from_raw_le([0xffffffffbfffff0c, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff]);
		let mut y = y2.pow_mod(exp, p);
		
		if y_is_odd != y.is_odd() {
			y = (p - y) % p;
		}

		Ok(ECDSAPubKey { x, y })
	}
}

// #[derive(Debug)]
// pub enum HashType {
// 	SigHashAll = 0x01,
// 	SigHashNone = 0x02,
// 	SigHashSingle = 0x03,
// 	SigHashAnyoneCanPay = 0x80,
// }

// impl TryFrom<u8> for HashType {
// 	type Error = Err;
// 	fn try_from(n: u8) -> Result<Self> {
// 		match n {
// 			0x01 => Ok(HashType::SigHashAll),
// 			0x02 => Ok(HashType::SigHashNone),
// 			0x03 => Ok(HashType::SigHashSingle),
// 			0x80 => Ok(HashType::SigHashAnyoneCanPay),
// 			_ => Err(Err::ValueError("invalid hash type".to_owned()))
// 		}
// 	}
// }

#[derive(Debug)]
pub struct ECDSASig {
	r: u256,
	s: u256,
	hash_type: u8,//HashType,
}

impl ECDSASig {
	pub fn hash_type(&self) -> u8 {//HashType {
		self.hash_type
	}

	pub fn new(r: u256, s: u256) -> ECDSASig {
		ECDSASig { r, s, hash_type: 1 }
	}
}

impl std::convert::TryFrom<&str> for ECDSASig {
	type Error = Err;
	fn try_from(s: &str) -> Result<ECDSASig> {
		ECDSASig::deserialize(&mut &*hex_to_bytes(s)?)
	}
}

impl ToJson for ECDSASig {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("s", JsonValue::string(format!("{}", self.s))),
			("r", JsonValue::string(format!("{}", self.r))),
			// ("hash_type", JsonValue::string(format!("{:?}", self.hash_type))),
			("hash_type", JsonValue::number(self.hash_type)),
		])
	}
}

fn read_der_32_byte_int(stream: &mut dyn Read) -> Result<(u8, [u8; 32])> {
	// "int" indicator
	if read_u8(stream)? != 0x02 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	let size = read_u8(stream)?;
	if size < 32 || size > 33 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	} else if size == 33 && read_u8(stream)? != 0 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	let mut value = [0; 32];
	read_buf_exact(stream, &mut value)?;
	let temp = value.iter().copied().rev().collect::<Vec<_>>();
	value.copy_from_slice(&temp);
	if size == 33 && value[0] < 0x80 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	Ok(((size == 33) as u8, value))
}

impl Deserialize for ECDSASig {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		// "compound structure" indicator
		if read_u8(stream)? != 0x30 {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}
		let total_size = read_u8(stream)?;
		if total_size < 68 || total_size > 70 {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}
		let (r_extra_byte, r) = read_der_32_byte_int(stream)?;
		let (s_extra_byte, s) = read_der_32_byte_int(stream)?;
		if total_size != 68 + r_extra_byte + s_extra_byte {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}

		let hash_type = read_u8(stream)?;//.try_into()?;

		Ok(ECDSASig{s: s.into(), r: r.into(), hash_type})
	}
}

#[test]
fn test_decompress() {
	// first item: compressed pub key (i.e. x coord preceded by 0x02 or 0x03)
	// second item: y coord
	let keys = [
		("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737", "8ec38ff91d43e8c2092ebda601780485263da089465619e0358a5c1be7ac91f4"),
		("0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898", "d6881e81d2e0163348ff07b3a9a3968401572aa79c79e7edb522f41addc8e6ce"),
		("02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27", "4d335b71c85e064f80191e1f7e2437afa676a3e2a5a5fafcf0d27940cd33e4b4"),
	];

	for (compressed, expected_y) in keys {
		let key = ECDSAPubKey::deserialize(&mut &*hex_to_bytes(compressed).unwrap()).unwrap();
		assert!(u256::hex(expected_y) == key.y);
	}
}

// #[test]
// fn test_tangents() {
// 	let points = [
// 		(ECDSAPoint::Coord { x: 5.into(), y: 11.into() }, u256::from(2), u256::from(17),   u256::from(12)), 
// 		(ECDSAPoint::Coord { x: 1.into(), y:  3.into() }, u256::from(4), u256::from(2773), u256::from(2312)), 
// 	];

// 	for (point, a, p, expected) in points {
// 		let tangent = point.tangent(a, p);
// 		println!("tangent:  {}\nexpected: {}", tangent, expected);
// 		assert!(expected == tangent);
// 	}
// }

#[test]
fn test_double_points() {
	let points = [
		(
			ECDSA_BASE,
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
				y: u256::hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
				y: u256::hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13"),
				y: u256::hex("51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13"),
				y: u256::hex("51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01"),
				y: u256::hex("5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01"),
				y: u256::hex("5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A"),
				y: u256::hex("F7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821"),
			},
		),
	];

	for (point, a, p, expected) in points {
		let point = point.double(a, p);
		println!("{:X}", point.x().unwrap());
		println!("{:X}", point.y().unwrap());
		assert!(point == expected);
	}
}

#[test]
fn test_add_points() {
	let points = [
		(
			ECDSAPoint::Coord {
				x: u256::hex("5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC"),
				y: u256::hex("C136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58"),
			},
			ECDSAPoint::Coord {
				x: u256::hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
				y: u256::hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97"),
				y: u256::hex("12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
				y: u256::hex("388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
			},
			ECDSAPoint::Coord {
				x: u256::hex("5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC"),
				y: u256::hex("6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7"),
				y: u256::hex("893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC"),
				y: u256::hex("6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"),
			},
			ECDSAPoint::Coord {
				x: u256::hex("2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01"),
				y: u256::hex("5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904"),
			},
			u256::from(ECDSA_A),
			u256::from(ECDSA_PRIME),
			ECDSAPoint::Coord {
				x: u256::hex("D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E"),
				y: u256::hex("581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58"),
			},
		),
	];

	for (p, q, a, prime, expected) in points {
		assert!(p.add(&q, a, prime) == expected);
	}
}

#[test]
fn test_mul_point_scalar() {
	let points = [
		(
			ECDSAPoint::Coord {
				x: u256::hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
				y: u256::hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
			},
			u256::dec("16"),
			ECDSAPoint::Coord {
				x: u256::hex("E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A"),
				y: u256::hex("F7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821"),
			},
		),
		(
			ECDSAPoint::Coord {
				x: u256::hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
				y: u256::hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
			},
			u256::dec("115792089237316195423570985008687907852837564279074904382605163141518161494323"),
			ECDSAPoint::Coord {
				x: u256::hex("499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4"),
				y: u256::hex("353D093B4AB17AAE6F0FBB1B584C2B9BB9BD863D85C06A4339A0BF2AFC5EBCD4"),
			},
		),
	];

	for (p, s, expected) in points {
		assert!(s * p == expected);
	}
}

#[test]
fn test_verify() {
	let sigs = [
		(
			// ECDSAPubKey {
			// 	x: u256::dec("8077278579061990400249759952135267692351268034085864289451880299432711854684"),
			// 	y: u256::dec("80909081783613153892905690721223288132374970267791400411164949654933991592611"),
			// },
			// ECDSASig {
			// 	r: u256::dec("29763811306752682825656922964074679856867562167831755660799482687659085743438"),
			// 	s: u256::dec("4123030547342669934053630013362611582222837609180400898674750749315497596184"),
			// 	hash_type: 1
			// },
			// Sha256::try_from("a1629e004eb3d703ecf3807f976e402a626d84c559f8eab1450adf207619f319").unwrap(),
			ECDSAPubKey {
				x: u256::dec("11417592243162659787639117474526594937691461953455800971979147078584873533825"),
				y: u256::dec("3417463964140656140894012168784011180671405399515445152471501642349140939185"),
			},
			ECDSASig {
				r: u256::dec("94785161033224446731240870469048275665961873467030210618040226616800059291665"),
				s: u256::dec("87967106749861467156284038218437790708843387091517171079593211170958407329199"),
				hash_type: 1
			},
			super::sha256::compute_sha256("message".as_bytes()),
		),
	];

	for (pubkey, sig, hash) in sigs {
		assert!(pubkey.verify(&sig, &hash));
	}
}