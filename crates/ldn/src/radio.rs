use crate::iface::{IfaceError, checked_ifindex, wiphy_index};
use crate::sys::{KernelContext, add_neighbor, if_add_ip, if_down, sysctl};
use crate::wireless::NL80211_IFTYPE_STATION;
use crate::wireless::Wireless;
use crate::wlan::MacAddress;

pub const LEGACY_VIF_NAMES: [&str; 4] = ["ldn", "ldn-mon", "ldn-tap", "ldnclient"];

#[derive(Debug, Clone)]
pub struct VifNames {
	pub owned: Vec<String>,
}

impl Default for VifNames {
	fn default() -> Self {
		Self {
			owned: LEGACY_VIF_NAMES
				.iter()
				.map(|name| (*name).to_owned())
				.collect(),
		}
	}
}

impl VifNames {
	#[must_use]
	pub fn with(names: &[&str]) -> Self {
		let mut owned: Vec<String> = LEGACY_VIF_NAMES
			.iter()
			.map(|name| (*name).to_owned())
			.collect();

		for name in names {
			if !owned.iter().any(|existing| existing == name) {
				owned.push((*name).to_owned());
			}
		}

		Self { owned }
	}

	#[must_use]
	pub fn owns(&self, name: &str) -> bool {
		self.owned.iter().any(|owned| owned == name)
	}
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
	pub deleted: Vec<String>,
	pub downed: Vec<String>,
	pub kept: Vec<String>,
}

/// # Errors
/// [`RadioError`] if the phy cannot be found or the interface dump fails, which means nothing was
/// swept at all.
pub fn free_radio(
	ctx: KernelContext,
	phyname: &str,
	names: &VifNames,
	keep: Option<&str>,
) -> Result<Swept, RadioError> {
	let wireless = Wireless::lkl(ctx);

	let wiphy = wiphy_index(&wireless, phyname)?;

	let mut swept = Swept::default();

	for interface in wireless.interfaces(Some(wiphy))? {
		let Some(name) = interface.name.clone() else {
			continue;
		};

		if keep == Some(name.as_str()) {
			swept.kept.push(name);
			continue;
		}

		// Deletion is reserved for station vifs. That is the case it exists for: a failed join
		// leaves one still associated, and the next association is then refused with nl80211
		// status code 1 until it is gone. Everything else only has to stop holding the radio,
		// and bringing it down does that.
		let is_station = interface.iftype == Some(NL80211_IFTYPE_STATION);

		if names.owns(&name) && is_station && wireless.del_interface(interface.index).is_ok() {
			swept.deleted.push(name);
			continue;
		}

		if let Ok(ifindex) = checked_ifindex(interface.index)
			&& if_down(ctx, ifindex).is_ok()
		{
			swept.downed.push(name);
		}
	}

	Ok(swept)
}

#[derive(Debug)]
pub enum RadioError {
	Iface(IfaceError),
	Sys(crate::sys::SysError),
}

impl core::fmt::Display for RadioError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Iface(err) => write!(f, "{err}"),
			Self::Sys(err) => write!(f, "{err}"),
		}
	}
}

impl core::error::Error for RadioError {}

impl From<IfaceError> for RadioError {
	fn from(err: IfaceError) -> Self {
		Self::Iface(err)
	}
}

impl From<crate::sys::SysError> for RadioError {
	fn from(err: crate::sys::SysError) -> Self {
		Self::Sys(err)
	}
}

#[cfg(test)]
mod tests {
	use super::{LEGACY_VIF_NAMES, VifNames};

	#[test]
	fn the_default_name_set_is_the_legacy_one() {
		let names = VifNames::default();

		for legacy in LEGACY_VIF_NAMES {
			assert!(names.owns(legacy), "{legacy} should be swept");
		}
	}

	#[test]
	fn configured_names_are_added_without_duplicating_the_legacy_ones() {
		let names = VifNames::with(&["ldn-sta", "ldn-mon"]);

		assert!(names.owns("ldn-sta"), "a configured name is ours");
		assert!(names.owns("ldn-mon"), "and so is a legacy one");
		assert_eq!(
			names.owned.iter().filter(|name| *name == "ldn-mon").count(),
			1,
			"a name that is both configured and legacy appears once"
		);
	}

	#[test]
	fn an_interface_we_did_not_make_is_not_ours_to_delete() {
		let names = VifNames::default();

		assert!(!names.owns("wlan0"));
		assert!(!names.owns("phy0"));
	}
}

/// # Errors
/// [`RadioError::Sys`] if the address cannot be added. The sysctls are best-effort: a kernel built
/// without one of them should not fail a join that would otherwise work.
pub fn tune_iface(
	ctx: KernelContext,
	ifname: &str,
	ifindex: i32,
	address: [u8; 4],
) -> Result<Tuned, RadioError> {
	let mut tuned = Tuned::default();

	// Reverse-path filtering drops the host's broadcast before any socket sees it: it arrives on an
	// interface whose route table does not associate it with that source. `accept_local` is the
	// matching permission for traffic that appears to come from our own subnet.
	//
	// All three scopes matter. `all` is combined with the per-interface value by taking the
	// maximum, so leaving `all` at 1 silently overrides the interface's 0.
	for (path, value) in [
		(format!("net.ipv4.conf.{ifname}.rp_filter"), "0"),
		("net.ipv4.conf.all.rp_filter".to_owned(), "0"),
		("net.ipv4.conf.default.rp_filter".to_owned(), "0"),
		(format!("net.ipv4.conf.{ifname}.accept_local"), "1"),
	] {
		if sysctl(ctx, &path, value).is_ok() {
			tuned.sysctls.push(path);
		}
	}

	if_add_ip(ctx, ifindex, address, LDN_PREFIX_LEN)?;
	tuned.address = Some(address);

	Ok(tuned)
}

/// LDN peers do not answer ARP, so the first packet to one would otherwise be dropped while the
/// kernel waits for a reply that never comes.
pub fn add_neighbors(
	ctx: KernelContext,
	ifindex: i32,
	peers: impl IntoIterator<Item = ([u8; 4], MacAddress)>,
) -> usize {
	let mut added = 0usize;

	for (address, mac) in peers {
		if add_neighbor(ctx, ifindex, address, mac.octets()).is_ok() {
			added += 1;
		}
	}

	added
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tuned {
	pub sysctls: Vec<String>,
	pub address: Option<[u8; 4]>,
}

/// LDN's addresses are always a `/24`: `169.254.<network>.<participant + 1>`.
const LDN_PREFIX_LEN: u32 = 24;
