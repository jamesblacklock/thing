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
const ECDSA_PRIME: u256 = u256::from_raw_le([0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
const ECDSA_ORDER: u256 = u256::from_raw_le([0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff]);
const ECDSA_A:     u256 = u256::from_raw_le([1, 0, 0, 0]);
const ECDSA_B:     u256 = u256::from_raw_le([7, 0, 0, 0]);
const ECDSA_BASE: ECDSAPoint = ECDSAPoint::Coord {
	x: i256::from_raw_le([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
	y: i256::from_raw_le([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ECDSAPoint {
	Coord { x: i256, y: i256 },
	Infinity,
}

impl ECDSAPoint {
	fn tangent(&self, a: u256, p: u256) -> i256 {
		match self {
			ECDSAPoint::Infinity       => panic!("point at infinity has no tangent"),
			ECDSAPoint::Coord { x, y } => {
				// s = 3x² + a / 2y
				let x: i512 = x.resize();
				let y: i512 = y.resize();
				let a = a.resize_signed();
				let p = p.resize_signed();
				((i512::from(3) * x * x + a) * (y << 1).mod_inv(p).unwrap()).modulo(p).resize()
			}
		}
	}

	fn double(&self, a: u256, p: u256) -> ECDSAPoint {
		match self {
			ECDSAPoint::Infinity       => self.clone(),
			ECDSAPoint::Coord { x, y } => {
				let x = x.resize();
				let y = y.resize();
				let tangent: i512 = self.tangent(a, p).resize();
				let p = p.resize_signed();
				let new_x = (tangent * tangent - x - x).modulo(p);
				let new_y = (tangent * (x - new_x) - y).modulo(p);
				ECDSAPoint::Coord {
					x: new_x.resize(),
					y: new_y.resize(),
				}
			}
		}
	}

	fn add(&self, other: &ECDSAPoint, a: u256, p: u256) -> ECDSAPoint {
		match (&self, &other) {
			(&ECDSAPoint::Infinity, _) => other.clone(),
			(_, &ECDSAPoint::Infinity) => self.clone(),
			(&ECDSAPoint::Coord { x: px, y: py }, &ECDSAPoint::Coord { x: qx, y: qy }) => {
				if (px, py) == (qx, qy) {
					self.double(a, p)
				} else {
					let prime = p.resize_signed();
					let (px, py) = (px.resize::<I512>(), py.resize::<I512>());
					let (qx, qy) = (qx.resize::<I512>(), qy.resize::<I512>());
					let slope = ((py - qy) * (px - qx).mod_inv(prime).unwrap()).modulo(prime);
					let new_x = (slope * slope - px - qx).modulo(prime);
					let new_y = (slope * (px - new_x) - py).modulo(prime);
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

impl std::ops::Mul<ECDSAPoint> for i512 {
	type Output = ECDSAPoint;
	fn mul(self, point: ECDSAPoint) -> ECDSAPoint {
		ECDSAPoint::mul(&point, self.to_unsigned().resize(), ECDSA_A, ECDSA_PRIME)
	}
}

impl std::ops::Neg for ECDSAPoint {
	type Output = ECDSAPoint;
	fn neg(self) -> ECDSAPoint {
		match self {
			ECDSAPoint::Infinity       => self,
			ECDSAPoint::Coord { x, y } => ECDSAPoint::Coord { x, y: -y },
		}
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

pub struct ECDSAPubKey {
	x: i256,
	y: i256,
}

impl ECDSAPubKey {
	fn to_point(&self) -> ECDSAPoint {
		ECDSAPoint::Coord { x: self.x, y: self.y }
	}

	pub fn verify(&self, sig: ECDSASig, hash: Sha256) -> bool {
		// adapted from https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py (public domain)
		let hash: i512 = hash.to_u256().resize_signed();
		let g = ECDSA_BASE;
		let n: i512 = ECDSA_ORDER.resize_signed();
		let r: i512 = sig.r.resize_signed();
		let s: i512 = sig.s.resize_signed();
		if r < 1.into() || r > n - 1.into() {
			return false;
		} else if s < 1.into() || s > n - 1.into() {
			return false;
		}
		let c = s.mod_inv(n).unwrap();
		let u1 = (hash * c).modulo(n);
		let u2 = (r * c).modulo(n);
		let point = u1 * g + u2 * self.to_point();
		if let ECDSAPoint::Coord { x, .. } = point {
			let v = x.to_unsigned() % ECDSA_ORDER;
			v == r.to_unsigned().resize()
		} else {
			false
		}
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

		let x: u512 = u256::from(x).resize();
		let p: u512 = ECDSA_PRIME.resize();

		// y² = x³ + 7 mod p
		let y2 = (x.pow_mod(3.into(), p) + 7.into()) % p;

		// from an online source: "Secp256k1 is chosen in a special way so that the square root of y² is y²^((p+1)/4)"
		let exp = (p + 1.into()) / 4.into();
		let mut y = y2.pow_mod(exp, p);
		
		if y_is_odd != y.is_odd() {
			y = (p - y) % p;
		}

		Ok(ECDSAPubKey {
			x: x.resize().to_signed(),
			y: y.resize().to_signed(),
		})
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

pub struct ECDSASig {
	r: u256,
	s: u256,
	hash_type: u8,//HashType,
}

impl ECDSASig {
	pub fn hash_type(&self) -> u8 {//HashType {
		self.hash_type
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
fn decompress_pub_keys() {
	// first item: compressed pub key (i.e. x coord preceded by 0x02 or 0x03)
	// second item: y coord
	let keys = [
		("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737", "8ec38ff91d43e8c2092ebda601780485263da089465619e0358a5c1be7ac91f4"),
		("0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898", "d6881e81d2e0163348ff07b3a9a3968401572aa79c79e7edb522f41addc8e6ce"),
		("02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27", "4d335b71c85e064f80191e1f7e2437afa676a3e2a5a5fafcf0d27940cd33e4b4"),
	];

	for (compressed, expected_y) in keys {
		let key = ECDSAPubKey::deserialize(&mut &*hex_to_bytes(compressed).unwrap()).unwrap();
		assert!(i256::hex(expected_y) == key.y);
	}
}

#[test]
fn tangents() {
	let points = [
		(ECDSAPoint::Coord { x: 5.into(), y: 11.into() }, u256::from(2), u256::from(17),   i256::from(12)), 
		(ECDSAPoint::Coord { x: 1.into(), y:  3.into() }, u256::from(4), u256::from(2773), i256::from(2312)), 
	];

	for (point, a, p, expected) in points {
		assert!(expected == point.tangent(a, p));
	}
}

#[test]
fn double_points() {
	let points = [
		(ECDSAPoint::Coord { x: 5.into(), y: 11.into() }, u256::from(2), u256::from(17), ECDSAPoint::Coord { x: 15.into(), y: 5.into() }),
	];

	for (point, a, p, expected) in points {
		assert!(point.double(a, p) == expected);
	}
}

#[test]
fn add_points() {
	let points = [
		(
			ECDSAPoint::Coord { x: 5.into(), y: 11.into() }, 
			ECDSAPoint::Coord { x: 15.into(), y: 5.into() },
			u256::from(2), u256::from(17),
			ECDSAPoint::Coord { x: 13.into(), y: 4.into() },
		),
	];

	for (p, q, a, prime, expected) in points {
		assert!(p.add(&q, a, prime) == expected);
	}
}