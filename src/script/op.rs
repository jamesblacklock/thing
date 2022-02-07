use std::fmt;

const OP_0: u8                   = 0;
const OP_PUSHDATA1: u8           = 76;
const OP_PUSHDATA2: u8           = 77;
const OP_PUSHDATA4: u8           = 78;
const OP_1NEGATE: u8             = 79;
const OP_RESERVED: u8            = 80;
const OP_1: u8                   = 81;
const OP_2: u8                   = 82;
const OP_3: u8                   = 83;
const OP_4: u8                   = 84;
const OP_5: u8                   = 85;
const OP_6: u8                   = 86;
const OP_7: u8                   = 87;
const OP_8: u8                   = 88;
const OP_9: u8                   = 89;
const OP_10: u8                  = 90;
const OP_11: u8                  = 91;
const OP_12: u8                  = 92;
const OP_13: u8                  = 93;
const OP_14: u8                  = 94;
const OP_15: u8                  = 95;
const OP_16: u8                  = 96;
const OP_NOP: u8                 = 97;
const OP_VER: u8                 = 98;
const OP_IF: u8                  = 99;
const OP_NOTIF: u8               = 100;
const OP_VERIF: u8               = 101;
const OP_VERNOTIF: u8            = 102;
const OP_ELSE: u8                = 103;
const OP_ENDIF: u8               = 104;
const OP_VERIFY: u8              = 105;
const OP_RETURN: u8              = 106;
const OP_TOALTSTACK: u8          = 107;
const OP_FROMALTSTACK: u8        = 108;
const OP_2DROP: u8               = 109;
const OP_2DUP: u8                = 110;
const OP_3DUP: u8                = 111;
const OP_2OVER: u8               = 112;
const OP_2ROT: u8                = 113;
const OP_2SWAP: u8               = 114;
const OP_IFDUP: u8               = 115;
const OP_DEPTH: u8               = 116;
const OP_DROP: u8                = 117;
const OP_DUP: u8                 = 118;
const OP_NIP: u8                 = 119;
const OP_OVER: u8                = 120;
const OP_PICK: u8                = 121;
const OP_ROLL: u8                = 122;
const OP_ROT: u8                 = 123;
const OP_SWAP: u8                = 124;
const OP_TUCK: u8                = 125;
const OP_CAT: u8                 = 126;
const OP_SUBSTR: u8              = 127;
const OP_LEFT: u8                = 128;
const OP_RIGHT: u8               = 129;
const OP_SIZE: u8                = 130;
const OP_INVERT: u8              = 131;
const OP_AND: u8                 = 132;
const OP_OR: u8                  = 133;
const OP_XOR: u8                 = 134;
const OP_EQUAL: u8               = 135;
const OP_EQUALVERIFY: u8         = 136;
const OP_RESERVED1: u8           = 137;
const OP_RESERVED2: u8           = 138;
const OP_1ADD: u8                = 139;
const OP_1SUB: u8                = 140;
const OP_2MUL: u8                = 141;
const OP_2DIV: u8                = 142;
const OP_NEGATE: u8              = 143;
const OP_ABS: u8                 = 144;
const OP_NOT: u8                 = 145;
const OP_0NOTEQUAL: u8           = 146;
const OP_ADD: u8                 = 147;
const OP_SUB: u8                 = 148;
const OP_MUL: u8                 = 149;
const OP_DIV: u8                 = 150;
const OP_MOD: u8                 = 151;
const OP_LSHIFT: u8              = 152;
const OP_RSHIFT: u8              = 153;
const OP_BOOLAND: u8             = 154;
const OP_BOOLOR: u8              = 155;
const OP_NUMEQUAL: u8            = 156;
const OP_NUMEQUALVERIFY: u8      = 157;
const OP_NUMNOTEQUAL: u8         = 158;
const OP_LESSTHAN: u8            = 159;
const OP_GREATERTHAN: u8         = 160;
const OP_LESSTHANOREQUAL: u8     = 161;
const OP_GREATERTHANOREQUAL: u8  = 162;
const OP_MIN: u8                 = 163;
const OP_MAX: u8                 = 164;
const OP_WITHIN: u8              = 165;
const OP_RIPEMD160: u8           = 166;
const OP_SHA1: u8                = 167;
const OP_SHA256: u8              = 168;
const OP_HASH160: u8             = 169;
const OP_HASH256: u8             = 170;
const OP_CODESEPARATOR: u8       = 171;
const OP_CHECKSIG: u8            = 172;
const OP_CHECKSIGVERIFY: u8      = 173;
const OP_CHECKMULTISIG: u8       = 174;
const OP_CHECKMULTISIGVERIFY: u8 = 175;

#[allow(non_camel_case_types)]
pub enum Op<'a> {
	OP_0,
	OP_DATA(&'a[u8]),
	OP_PUSHDATA1(&'a[u8]),
	OP_PUSHDATA2(&'a[u8]),
	OP_PUSHDATA4(&'a[u8]),
	OP_1,
	OP_2,
	OP_3,
	OP_4,
	OP_5,
	OP_6,
	OP_7,
	OP_8,
	OP_9,
	OP_10,
	OP_11,
	OP_12,
	OP_13,
	OP_14,
	OP_15,
	OP_16,
	OP_RETURN,
	OP_DUP,
	OP_EQUAL,
	OP_EQUALVERIFY,
	OP_HASH160,
	OP_CHECKSIG,
	// OP_CHECKLOCKTIMEVERIFY
	// OP_NOP2
	// OP_NOP
	// OP_CHECKSEQUENCEVERIFY
	// OP_NOP3
	// OP_PUBKEYHASH
	// OP_HASH160
	// OP_PUBKEY
	// OP_CHECKSIG
	// OP_INVALIDOPCODE
	// OP_IF
	// OP_VER
	// OP_IF
	// OP_VERIF
	// OP_IF
	// OP_VERNOTIF
	// OP_IF
	// OP_RESERVED1
	// OP_IF
	// OP_RESERVED2
	// OP_IF
	// OP_NOP1
	// OP_NOP4
	// OP_NOP10
	Unknown(u8),
}

fn fmt_data(f: &mut fmt::Formatter, op: &str, data: &[u8]) -> fmt::Result {
	write!(f, "{}", op)?;
	for &b in data.iter() {
		write!(f, "{:02x}", b)?;
	}
	Ok(())
}

impl <'a> Op<'a> {
    pub fn next(it: &mut super::ScriptIterator<'a>) -> Self {
        let opcode = it.next_u8();
		match opcode {
			OP_0           => Op::OP_0,
			x @ 1..=75     => Op::OP_DATA(it.next_slice(x as usize)),
			OP_PUSHDATA1   => {
				let size = it.next_u8() as usize;
				Op::OP_PUSHDATA1(it.next_slice(size))
			},
			OP_PUSHDATA2   => {
				let size = it.next_u16() as usize;
				Op::OP_PUSHDATA2(it.next_slice(size))
			},
			OP_PUSHDATA4   => {
				let size = it.next_u32() as usize;
				Op::OP_PUSHDATA4(it.next_slice(size))
			},
			OP_1           => Op::OP_1,
			OP_2           => Op::OP_2,
			OP_3           => Op::OP_3,
			OP_4           => Op::OP_4,
			OP_5           => Op::OP_5,
			OP_6           => Op::OP_6,
			OP_7           => Op::OP_7,
			OP_8           => Op::OP_8,
			OP_9           => Op::OP_9,
			OP_10          => Op::OP_10,
			OP_11          => Op::OP_11,
			OP_12          => Op::OP_12,
			OP_13          => Op::OP_13,
			OP_14          => Op::OP_14,
			OP_15          => Op::OP_15,
			OP_16          => Op::OP_16,
			OP_RETURN      => Op::OP_RETURN,
			OP_DUP         => Op::OP_DUP,
			OP_EQUAL       => Op::OP_EQUAL,
			OP_EQUALVERIFY => Op::OP_EQUALVERIFY,
			OP_HASH160     => Op::OP_HASH160,
			OP_CHECKSIG    => Op::OP_CHECKSIG,
			b              => Op::Unknown(b),
		}
    }
}

impl <'a> fmt::Display for Op<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Op::OP_0               => write!(f, "OP_0"),
			Op::OP_DATA(data)      => fmt_data(f, "", data),
			Op::OP_PUSHDATA1(data) => fmt_data(f, "OP_PUSHDATA1 ", data),
			Op::OP_PUSHDATA2(data) => fmt_data(f, "OP_PUSHDATA2 ", data),
			Op::OP_PUSHDATA4(data) => fmt_data(f, "OP_PUSHDATA4 ", data),
			Op::OP_1               => write!(f, "OP_1"),
			Op::OP_2               => write!(f, "OP_2"),
			Op::OP_3               => write!(f, "OP_3"),
			Op::OP_4               => write!(f, "OP_4"),
			Op::OP_5               => write!(f, "OP_5"),
			Op::OP_6               => write!(f, "OP_6"),
			Op::OP_7               => write!(f, "OP_7"),
			Op::OP_8               => write!(f, "OP_8"),
			Op::OP_9               => write!(f, "OP_9"),
			Op::OP_10              => write!(f, "OP_10"),
			Op::OP_11              => write!(f, "OP_11"),
			Op::OP_12              => write!(f, "OP_12"),
			Op::OP_13              => write!(f, "OP_13"),
			Op::OP_14              => write!(f, "OP_14"),
			Op::OP_15              => write!(f, "OP_15"),
			Op::OP_16              => write!(f, "OP_16"),
			Op::OP_DUP             => write!(f, "OP_DUP"),
			Op::OP_RETURN          => write!(f, "OP_RETURN"),
			Op::OP_EQUALVERIFY     => write!(f, "OP_EQUALVERIFY"),
			Op::OP_EQUAL           => write!(f, "OP_EQUAL"),
			Op::OP_HASH160         => write!(f, "OP_HASH160"),
			Op::OP_CHECKSIG        => write!(f, "OP_CHECKSIG"),
			Op::Unknown(b)         => write!(f, "0x{:x}??", b),
		}
	}
}