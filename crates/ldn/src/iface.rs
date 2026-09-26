use crate::sys::SysError;
use crate::sys::{KernelContext, sysctl};
use crate::wireless::Interface;
use crate::wireless::Wireless;

#[derive(Debug)]
pub enum IfaceError {
	Sys(SysError),
	NoSuchPhy { name: String },
	BadInterfaceIndex { index: u32 },
}

impl core::fmt::Display for IfaceError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Sys(err) => write!(f, "{err}"),
			Self::NoSuchPhy { name } => write!(f, "no wireless device called {name}"),
			Self::BadInterfaceIndex { index } => write!(f, "implausible interface index {index}"),
		}
	}
}

impl core::error::Error for IfaceError {}

impl From<SysError> for IfaceError {
	fn from(err: SysError) -> Self {
		Self::Sys(err)
	}
}

/// # Errors
/// [`IfaceError::NoSuchPhy`] if there is no such device, or [`IfaceError::Sys`] if the kernel
/// cannot be asked.
pub fn wiphy_index(wireless: &Wireless, phyname: &str) -> Result<u32, IfaceError> {
	wireless
		.find_wiphy(phyname)?
		.ok_or_else(|| IfaceError::NoSuchPhy {
			name: phyname.to_owned(),
		})
}

/// # Errors
/// [`IfaceError`] if the kernel refuses any step, or if the interface cannot be found afterwards.
pub fn ensure_interface(
	wireless: &Wireless,
	wiphy: u32,
	ifname: &str,
	iftype: u32,
	monitor_other_bss: bool,
) -> Result<Interface, IfaceError> {
	let existing = wireless
		.interfaces(Some(wiphy))?
		.into_iter()
		.find(|interface| interface.name.as_deref() == Some(ifname));

	if let Some(interface) = existing {
		if interface.iftype == Some(iftype) {
			return Ok(interface);
		}
		wireless.del_interface(interface.index)?;
	}

	Ok(wireless.new_interface(wiphy, ifname, iftype, monitor_other_bss)?)
}

/// # Errors
/// [`IfaceError::BadInterfaceIndex`] if it does not fit, which would mean the kernel reported
/// something impossible.
pub fn checked_ifindex(index: u32) -> Result<i32, IfaceError> {
	i32::try_from(index).map_err(|_| IfaceError::BadInterfaceIndex { index })
}

/// Keeps IPv6 off `ifname`. Call it between creating the interface and bringing it up.
///
/// LDN is IPv4 only. Left on, IPv6 greets every new link with a duplicate-address probe and an MLD
/// report, which go out on the host's network the moment the station associates or the AP starts.
/// Best-effort, like the sysctls in [`crate::radio::tune_iface`]: a kernel built without IPv6 has
/// no such sysctl, and nothing to switch off.
pub fn disable_ipv6(ctx: KernelContext, ifname: &str) {
	let _ = sysctl(ctx, &format!("net.ipv6.conf.{ifname}.disable_ipv6"), "1");
}
