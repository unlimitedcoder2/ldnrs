use crate::protocol::WireRead;

macro_rules! wire_enum {
	(
		$(#[$meta:meta])*
		$name:ident : $repr:ty {
			$($(#[$variant_meta:meta])* $variant:ident = $value:expr),* $(,)?
		}
	) => {
		$(#[$meta])*
		// No `#[repr]`: it is not allowed on an enum with no variants, which `NwmOp` is for now.
		// The explicit discriminants stay so that two variants sharing a value fail to compile.
		#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
		pub enum $name {
			$($(#[$variant_meta])* $variant = $value),*
		}

		impl $name {
			#[must_use]
			pub const fn value(self) -> $repr {
				match self {
					$(Self::$variant => $value,)*
				}
			}

			#[must_use]
			pub const fn from_value(value: $repr) -> Option<Self> {
				match value {
					$($value => Some(Self::$variant),)*
					_ => None,
				}
			}

			#[must_use]
			pub const fn name(self) -> &'static str {
				match self {
					$(Self::$variant => stringify!($variant),)*
				}
			}
		}
	};
}

wire_enum! {
	Op: u8 {
		Hello = 0x01,
		SubscribeLog = 0x02,
		Shutdown = 0x03,

		/// `sub_op` is an [`LdnOp`].
		Ldn = 0x10,
		/// `sub_op` is an [`NwmOp`].
		Nwm = 0x11,

		Reply = 0x80,
		Event = 0x81,
		Data = 0x82,
	}
}

wire_enum! {
	/// The `sub_op` of an [`Op::Ldn`] frame.
	LdnOp: u8 {
		Scan = 0x20,
		ScanCancel = 0x21,

		Connect = 0x30,
		CreateNetwork = 0x31,
		CloseNetwork = 0x32,
		GetNetworkInfo = 0x33,

		/// Access point only.
		SetApplicationData = 0x40,
		/// Access point only.
		SetAcceptPolicy = 0x41,
		/// Access point only.
		SetAcceptFilter = 0x42,
		/// Access point only; by participant index.
		Kick = 0x43,

		OpenDatagram = 0x50,
		OpenRaw = 0x51,
		CloseChannel = 0x52,

		SetProdKeys = 0x60,
		HasProdKeys = 0x61,
	}
}

wire_enum! {
	/// The `sub_op` of an [`Op::Nwm`] frame. None yet.
	#[allow(clippy::empty_enums, reason = "NWM is scaffolding; its operations come later")]
	NwmOp: u8 {}
}

wire_enum! {
	Status: u8 {
		None = 0,
		BadRequest = 1,
		UnsupportedVersion = 2,
		InvalidHandle = 3,
		InvalidParam = 4,
		Busy = 5,
		NoRadio = 6,
		NoKeys = 7,
		NotFound = 8,
		Timeout = 9,
		/// LDN authentication failed; the reply's `auth_status` has the sub-code.
		AuthFailed = 10,
		Io = 11,
		Unsupported = 12,
		Internal = 13,
	}
}

wire_enum! {
	EventKind: u8 {
		NetworkFound = 1,
		ScanDone = 2,
		Join = 3,
		Leave = 4,
		Disconnect = 5,
		AppDataChanged = 6,
		PolicyChanged = 7,
		ChannelError = 8,
		Log = 9,
		RadioState = 10,
		LogDropped = 11,
	}
}

wire_enum! {
	Backend: u8 {
		Lkl = 0,
		Host = 1,
		Esp32 = 2
	}
}

wire_enum! {
	WirelessProtocol: u8 {
		Ldn = 0,
		/// Nintendo 3DS local wireless.
		Nwm = 1,
	}
}

impl WireRead for WirelessProtocol {
	fn get(reader: &mut super::Reader<'_>) -> Result<Self, super::DecodeError> {
		let val = reader.u8()?;

		Self::from_value(val).ok_or_else(|| super::DecodeError::InvalidVariant {
			enum_name: "WirelessProtocol",
			val: usize::from(val),
		})
	}
}

wire_enum! {
	RadioState: u8 {
		Idle = 0,
		Attaching = 1,
		Ready = 2,
		Lost = 3,
		Failed = 4,
	}
}

pub const PROTOCOL_VERSION: u32 = 7;
