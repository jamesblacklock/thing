use std::{iter::IntoIterator, fmt};

pub enum JsonValue {
	Null,
	String(String),
	Number(f64),
	Bool(bool),
	Object(Vec<(String, JsonValue)>),
	Array(Vec<JsonValue>),
}

pub trait ToJson {
	fn to_json(&self) -> JsonValue;
}

pub trait IntoF64 { fn into_f64(self) -> f64; }
impl IntoF64 for u8 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for i8 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for u16 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for i16 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for u32 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for i32 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for u64 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for i64 { fn into_f64(self) -> f64 { self as f64 } }
impl IntoF64 for f32 { fn into_f64(self) -> f64 { self as f64 } }

impl JsonValue {
	pub fn null() -> JsonValue { JsonValue::Null }
	pub fn string<T: Into<String>>(s: T) -> JsonValue { JsonValue::String(s.into()) }
	pub fn number<T: IntoF64>(n: T) -> JsonValue { JsonValue::Number(n.into_f64()) }
	pub fn bool(b: bool) -> JsonValue { JsonValue::Bool(b) }
	pub fn object<T: IntoIterator<Item = (U, JsonValue)>, U: Into<String>>(a: T) -> JsonValue {
		JsonValue::Object(a.into_iter().map(|(k, v)| (k.into(), v)).collect())
	}
	pub fn array<T: IntoIterator<Item = JsonValue>>(a: T) -> JsonValue {
		JsonValue::Array(a.into_iter().collect())
	}

	fn fmt(&self, f: &mut fmt::Formatter, indent: usize) -> fmt::Result {
		match self {
			JsonValue::Null        => write!(f, "null"),
			JsonValue::String(s)   => JsonValue::fmt_string(f, s),
			JsonValue::Number(n)   => write!(f, "{}", n),
			JsonValue::Bool(b)     => write!(f, "{}", b),
			JsonValue::Object(map) => JsonValue::fmt_object(f, &map, indent),
			JsonValue::Array(vec)  => JsonValue::fmt_array(f, &vec, indent),
		}
	}

	fn fmt_string(f: &mut fmt::Formatter, s: &String) -> fmt::Result {
		write!(f, "\"")?;
		for c in s.chars() {
			match c {
				'\n'   => write!(f, "\\n")?,
				'\r'   => write!(f, "\\r")?,
				'\t'   => write!(f, "\\t")?,
				'\x0c' => write!(f, "\\f")?,
				'\x08' => write!(f, "\\b")?,
				'\\'   => write!(f, "\\\\")?,
				'"'    => write!(f, "\\\"")?,
				_      => write!(f, "{}", c)?,
			}
		}
		write!(f, "\"")
	}

	fn fmt_object(f: &mut fmt::Formatter, pairs: &Vec<(String, JsonValue)>, indent: usize) -> fmt::Result {
		write!(f, "{{\n")?;
		for (k, v) in pairs {
			write!(f, "{:>1$}", "", (indent + 1) * 4)?;
			JsonValue::fmt_string(f, k)?;
			write!(f, ": ")?;
			JsonValue::fmt(v, f, indent + 1)?;
			write!(f, ",\n")?;
		}
		write!(f, "{:>1$}}}", "", indent * 4)
	}

	fn fmt_array(f: &mut fmt::Formatter, vec: &Vec<JsonValue>, indent: usize) -> fmt::Result {
		write!(f, "[\n")?;
		for v in vec {
			write!(f, "{:>1$}", "", (indent + 1) * 4)?;
			JsonValue::fmt(v, f, indent + 1)?;
			write!(f, ",\n")?;
		}
		write!(f, "{:>1$}]", "", indent * 4)
	}
}

impl fmt::Display for JsonValue {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		JsonValue::fmt(self, f, 0)
	}
}