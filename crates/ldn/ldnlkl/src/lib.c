#include "lib.h"
#include "std.h"

#include <string.h>
#include <lkl-usb.h>
#include <lkl-wl.h>
#include <lkl.h>
#include <lkl/asm/host_ops.h>
#include <lkl/asm/syscalls.h>
#include <lkl/linux/if_ether.h>
#include <lkl/linux/if_packet.h>
#include <lkl/linux/in.h>
#include <lkl_host.h>

#include <stdlib.h>

typedef struct {
	LdnLklUsbOps             usb_ops;
	struct lkl_usb_host_ops  lkl_usb_ops;
	bool                     usb_attached;
} LklCtx;

void ldn_lkl_print_impl(const char *s, i32 len, void *userdata) { impl_ldn_lkl_print(s, len, userdata); }

i32 ldn_lkl_load_firmware_cb(const char *name, void **dest, long long unsigned int *size, void *userdata) {
	return impl_ldn_lkl_load_firmware(name, dest, size, userdata);
}

i32 ldn_lkl_init(void **ctx, void *userdata, const char *cmdline) {
	lkl_host_ops.userdata =      userdata;
	lkl_host_ops.print =         ldn_lkl_print_impl;
	lkl_host_ops.load_firmware = ldn_lkl_load_firmware_cb;

	lkl_printf("Initialising");

	i32 ret = lkl_init(&lkl_host_ops);
	if (ret < 0) {
		lkl_printf("lkl_init failed: %d (%s)\n", ret, lkl_strerror(ret));
		return -1;
	}

	lkl_printf("cmdline: %s\n", cmdline);

	ret = lkl_start_kernel("%s", cmdline);
	lkl_printf("lkl_start_kernel -> %d (%s)\n", ret, lkl_strerror(ret));

	if (ret < 0) {
		lkl_cleanup();
		return -1;
	}

	if (!lkl_is_running()) {
		lkl_printf("lkl kernel did not enter running state\n");
		lkl_cleanup();
		return -1;
	}

	void *c = malloc(sizeof(LklCtx));
	memset(c, 0, sizeof(LklCtx));
	*ctx = c;

	return 0;
}

void ldn_lkl_find_driver(void *ctx, i32 vid, i32 pid, void (*callback)(const char *fw, void *userdata),
						 void *userdata) {
	UNUSED(ctx);
	lkl_get_driverinfo(vid, pid, callback, userdata);
}

LdnLklUsbDriverType ldn_lkl_get_driver_type(void *ctx, int32_t vid, int32_t pid, const char **name) {
	UNUSED(ctx);
	enum lkl_usb_driver_type type = lkl_get_usb_driver_type(vid, pid, name);

	switch (type) {
		case LKL_USB_DRIVER_NONE: return     LDN_LKL_USB_DRIVER_NONE;
		case LKL_USB_DRIVER_UNKNOWN: return  LDN_LKL_USB_DRIVER_UNKNOWN;
		case LKL_USB_DRIVER_WIFI: return     LDN_LKL_USB_DRIVER_WIFI;
		case LKL_USB_DRIVER_ETHERNET: return LDN_LKL_USB_DRIVER_ETHERNET;
	}

	return LDN_LKL_USB_DRIVER_NONE;
}

static_assert(LDN_LKL_AF_NETLINK ==       LKL_AF_NETLINK,      "AF_NETLINK changed");
static_assert(LDN_LKL_AF_PACKET ==        LKL_AF_PACKET,       "AF_PACKET changed");
static_assert(LDN_LKL_SOCK_DGRAM ==       LKL_SOCK_DGRAM,      "SOCK_DGRAM changed");
static_assert(LDN_LKL_SOCK_RAW ==         LKL_SOCK_RAW,        "SOCK_RAW changed");
static_assert(LDN_LKL_NETLINK_ROUTE ==    LKL_NETLINK_ROUTE,   "NETLINK_ROUTE changed");
static_assert(LDN_LKL_NETLINK_GENERIC ==  LKL_NETLINK_GENERIC, "NETLINK_GENERIC changed");
static_assert(LDN_LKL_NETLINK_CAP_ACK ==  LKL_NETLINK_CAP_ACK, "NETLINK_CAP_ACK changed");
static_assert(LDN_LKL_NETLINK_EXT_ACK ==  LKL_NETLINK_EXT_ACK, "NETLINK_EXT_ACK changed");
static_assert(LDN_LKL_ETH_P_ALL ==        LKL_ETH_P_ALL,       "ETH_P_ALL changed");
static_assert(LDN_LKL_EAGAIN ==           LKL_EAGAIN,          "EAGAIN changed");
static_assert(LDN_LKL_EINTR ==            LKL_EINTR,           "EINTR changed");

static_assert(LDN_LKL_SOL_NETLINK == 270,          "SOL_NETLINK changed");
static_assert(LDN_LKL_AF_INET ==     LKL_AF_INET,  "AF_INET changed");
static_assert(LDN_LKL_AF_INET6 ==    LKL_AF_INET6, "AF_INET6 changed");

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ldn_htons(x) (x)
#define ldn_htonl(x) (x)
#else
#define ldn_htons(x) __builtin_bswap16(x)
#define ldn_htonl(x) __builtin_bswap32(x)
#endif
#define ldn_ntohs(x) ldn_htons(x)
#define ldn_ntohl(x) ldn_htonl(x)

i32 ldn_lkl_socket(void *ctx, i32 domain, i32 type, i32 protocol) {
	UNUSED(ctx);
	return (i32) lkl_sys_socket(domain, type, protocol);
}

i32 ldn_lkl_open_netlink(void *ctx, i32 family) {
	return ldn_lkl_socket(ctx, LKL_AF_NETLINK, LKL_SOCK_DGRAM, family);
}

i32 ldn_lkl_open_packet(void *ctx, u16 eth_protocol) {
	return ldn_lkl_socket(ctx, LKL_AF_PACKET, LKL_SOCK_RAW, ldn_htons(eth_protocol));
}

i32 ldn_lkl_bind(void *ctx, i32 fd, const void *addr, i32 addrlen) {
	UNUSED(ctx);
	return (i32) lkl_sys_bind(fd, (struct lkl_sockaddr *) addr, addrlen);
}

i32 ldn_lkl_setsockopt(void *ctx, i32 fd, i32 level, i32 optname, const void *value, i32 len) {
	UNUSED(ctx);
	return (i32) lkl_sys_setsockopt(fd, level, optname, (char *) value, len);
}

i32 ldn_lkl_setsockopt_int(void *ctx, i32 fd, i32 level, i32 optname, i32 value) {
	return ldn_lkl_setsockopt(ctx, fd, level, optname, &value, sizeof(value));
}

i32 ldn_lkl_set_recv_timeout_ms(void *ctx, i32 fd, u32 timeout_ms) {
	struct lkl_timeval tv = {
		.tv_sec = timeout_ms / 1000,
		.tv_usec = (timeout_ms % 1000) * 1000,
	};
	return ldn_lkl_setsockopt(ctx, fd, LKL_SOL_SOCKET, LKL_SO_RCVTIMEO, &tv, sizeof(tv));
}

i32 ldn_lkl_getsockname(void *ctx, i32 fd, void *addr, i32 *addrlen) {
	UNUSED(ctx);
	return (i32) lkl_sys_getsockname(fd, (struct lkl_sockaddr *) addr, addrlen);
}

i32 ldn_lkl_netlink_pid(void *ctx, i32 fd, u32 *pid) {
	struct lkl_sockaddr_nl sa = {0};
	i32 len = sizeof(sa);

	i32 ret = ldn_lkl_getsockname(ctx, fd, &sa, &len);
	if (ret < 0) {
		return ret;
	}
	if (len < (i32) sizeof(sa)) {
		return -LKL_EINVAL;
	}

	*pid = sa.nl_pid;
	return 0;
}

i64 ldn_lkl_sendto(void *ctx, i32 fd, const void *buf, i32 len, i32 flags, const void *dest,
				   i32 destlen) {
	UNUSED(ctx);
	return lkl_sys_sendto(fd, (void *) buf, len, flags, (struct lkl_sockaddr *) dest, destlen);
}

i64 ldn_lkl_recvfrom(void *ctx, i32 fd, void *buf, i32 len, i32 flags, void *addr, i32 *addrlen) {
	UNUSED(ctx);
	if (addr && !addrlen) {
		return -LKL_EINVAL;
	}

	return lkl_sys_recvfrom(fd, buf, len, flags, (struct lkl_sockaddr *) addr, addrlen);
}

i32 ldn_lkl_close(void *ctx, i32 fd) {
	UNUSED(ctx);
	return (i32) lkl_sys_close(fd);
}

i32 ldn_lkl_set_nonblock(void *ctx, i32 fd) {
	UNUSED(ctx);
	i32 fl = (i32) lkl_sys_fcntl(fd, LKL_F_GETFL, 0);
	if (fl < 0) {
		return fl;
	}
	return (i32) lkl_sys_fcntl(fd, LKL_F_SETFL, fl | LKL_O_NONBLOCK);
}

i32 ldn_lkl_sockaddr_nl(void *buf, i32 cap, u32 pid, u32 groups) {
	struct lkl_sockaddr_nl sa = {0};
	if (cap < (i32) sizeof(sa)) {
		return -LKL_EINVAL;
	}

	sa.nl_family = LKL_AF_NETLINK;
	sa.nl_pid = pid;
	sa.nl_groups = groups;

	memcpy(buf, &sa, sizeof(sa));
	return (i32) sizeof(sa);
}

i32 ldn_lkl_sockaddr_ll(void *buf, i32 cap, u16 eth_protocol, i32 ifindex) {
	struct lkl_sockaddr_ll sa = {0};
	if (cap < (i32) sizeof(sa))
		return -LKL_EINVAL;

	sa.sll_family = LKL_AF_PACKET;
	sa.sll_protocol = ldn_htons(eth_protocol);
	sa.sll_ifindex = ifindex;

	memcpy(buf, &sa, sizeof(sa));
	return (i32) sizeof(sa);
}

i32 ldn_lkl_sockaddr_in(void *buf, i32 cap, u32 addr, u16 port) {
	struct lkl_sockaddr_in sa = {0};
	if (cap < (i32) sizeof(sa)) {
		return -LKL_EINVAL;
	}

	sa.sin_family = LKL_AF_INET;
	sa.sin_port = ldn_htons(port);
	sa.sin_addr.lkl_s_addr = ldn_htonl(addr);

	memcpy(buf, &sa, sizeof(sa));
	return (i32) sizeof(sa);
}

i32 ldn_lkl_sockaddr_in_parse(const void *buf, i32 len, u32 *addr, u16 *port) {
	struct lkl_sockaddr_in sa;
	if (!buf || len < (i32) sizeof(sa)) {
		return -LKL_EINVAL;
	}

	memcpy(&sa, buf, sizeof(sa));
	if (sa.sin_family != LKL_AF_INET) {
		return -LKL_EINVAL;
	}

	if (addr) {
		*addr = ldn_ntohl(sa.sin_addr.lkl_s_addr);		
	}
	if (port) {
		*port = ldn_ntohs(sa.sin_port);
	}

	return 0;
}

i32 ldn_lkl_ifname_to_ifindex(void *ctx, const char *name) {
	UNUSED(ctx);
	return lkl_ifname_to_ifindex(name);
}

i32 ldn_lkl_if_up(void *ctx, i32 ifindex) {
	UNUSED(ctx);
	return lkl_if_up(ifindex);
}

i32 ldn_lkl_if_down(void *ctx, i32 ifindex) {
	UNUSED(ctx);
	return lkl_if_down(ifindex);
}

i32 ldn_lkl_if_set_mtu(void *ctx, i32 ifindex, i32 mtu) {
	UNUSED(ctx);
	return lkl_if_set_mtu(ifindex, mtu);
}

i32 ldn_lkl_if_add_ip(void *ctx, i32 ifindex, i32 af, const void *addr, u32 prefix_len) {
	UNUSED(ctx);
	return lkl_if_add_ip(ifindex, af, (void *) addr, prefix_len);
}

i32 ldn_lkl_if_del_ip(void *ctx, i32 ifindex, i32 af, const void *addr, u32 prefix_len) {
	UNUSED(ctx);
	return lkl_if_del_ip(ifindex, af, (void *) addr, prefix_len);
}

i32 ldn_lkl_add_neighbor(void *ctx, i32 ifindex, i32 af, const void *addr, const void *mac) {
	UNUSED(ctx);
	return lkl_add_neighbor(ifindex, af, (void *) addr, (void *) mac);
}

i32 ldn_lkl_sysctl(void *ctx, const char *path, const char *value) {
	UNUSED(ctx);
	if (!path || !value) {
		return -LKL_EINVAL;
	}

	static const char prefix[] = "/proc/sys/";
	const size_t plen = sizeof(prefix) - 1;
	const size_t n = strlen(path);

	char full[256] = {};
	if (n + 1 > sizeof(full) - plen) {
		return -LKL_EINVAL;
	}

	memcpy(full, prefix, plen);
	memcpy(full + plen, path, n + 1);

	for (char *p = full + plen; *p; p++) {
		if (*p == '.') {
			*p = '/';
		}
	}

	lkl_mount_fs("proc");

	i32 fd = (i32) lkl_sys_open(full, LKL_O_WRONLY, 0);
	if (fd < 0) {
		return fd;
	}

	i64 ret = lkl_sys_write(fd, (char *) value, strlen(value));
	lkl_sys_close(fd);

	return ret < 0 ? (i32) ret : 0;
}

static void *ldn_usb_submit_control(void *cookie, const struct lkl_usb_setup *setup, void *data) {
	LklCtx *context = cookie;
	return context->usb_ops.submit_control(context->usb_ops.cookie, (const unsigned char *) setup, data, setup->wLength);
}

static void *ldn_usb_submit_transfer(void *cookie,  unsigned char ep, void *data, int len) {
	LklCtx *context = cookie;
	return context->usb_ops.submit_transfer(context->usb_ops.cookie, ep, data, len);
}

static int ldn_usb_poll(void *cookie, void *handle, int *result) {
	LklCtx *context = cookie;
	return context->usb_ops.poll(context->usb_ops.cookie, handle, result);
}

static void ldn_usb_cancel(void *cookie, void *handle) {
	LklCtx *context = cookie;
	context->usb_ops. cancel(context->usb_ops.cookie, handle);
}

static void ldn_usb_release(void *cookie, void *handle) {
	LklCtx *context = cookie;
	context->usb_ops. release(context->usb_ops.cookie, handle);
}

static int ldn_usb_set_alt(void *cookie, unsigned char iface, unsigned char alt) {
	LklCtx *context = cookie;
	return context->usb_ops.set_alt(context->usb_ops.cookie, iface, alt);
}

i32 ldn_lkl_usb_attach(void *ctx, const LdnLklUsbOps *ops) {
	if (!ops ||
		!ops->submit_control ||
		!ops->submit_transfer ||
		!ops->poll ||
		!ops->cancel ||
		!ops->release ||
		!ops->set_alt
	) {
		return -LKL_EINVAL;
	}

	LklCtx *context = ctx;
	context->usb_ops  = *ops;
	context->lkl_usb_ops = (struct lkl_usb_host_ops){
		.submit_control = ldn_usb_submit_control,
		.submit_transfer = ldn_usb_submit_transfer,
		.poll = ldn_usb_poll,
		.cancel = ldn_usb_cancel,
		.release = ldn_usb_release,
		.set_alt = ldn_usb_set_alt,
		.cookie = context,
		.superspeed = ops->superspeed,
	};

	i32 ret = lkl_usb_attach(&context->lkl_usb_ops);
	if (ret < 0) {
		lkl_printf("lkl_usb_attach failed: %d (%s) - liblkl built without CONFIG_USB_LKL_HCD?\n",
				   ret, lkl_strerror(ret));
		return ret;
	}

	context->usb_attached = true;
	return ret;
}

i32 ldn_lkl_usb_detach(void *ctx) {
	LklCtx *context = ctx;

	if (!context->usb_attached) {
		return 0;
	}

	context->usb_attached = false;
	lkl_usb_detach();
	return 0;
}

i32 ldn_lkl_usb_completion_irq(void *ctx) {
	UNUSED(ctx);
	return lkl_usb_completion_irq();
}

void ldn_lkl_trigger_irq(void *ctx, i32 irq) {
	UNUSED(ctx);
	lkl_trigger_irq(irq);
}

static_assert(sizeof(LdnLklWlIface) == sizeof(struct lkl_wl_iface), "lkl_wl_iface changed");
static_assert(sizeof(LdnLklWlBss)   == sizeof(struct lkl_wl_bss),   "lkl_wl_bss changed");
static_assert(sizeof(LdnLklWlEvent) == sizeof(struct lkl_wl_event), "lkl_wl_event changed");

static_assert(offsetof(LdnLklWlIface, name) == offsetof(struct lkl_wl_iface, name),
			  "lkl_wl_iface layout changed");
static_assert(offsetof(LdnLklWlBss, ssid) == offsetof(struct lkl_wl_bss, ssid),
			  "lkl_wl_bss layout changed");
static_assert(offsetof(LdnLklWlEvent, lost) == offsetof(struct lkl_wl_event, lost),
			  "lkl_wl_event layout changed");

static_assert(LDN_LKL_WL_IFTYPE_STATION == LKL_WL_IFTYPE_STATION, "IFTYPE_STATION changed");
static_assert(LDN_LKL_WL_IFTYPE_AP      == LKL_WL_IFTYPE_AP,      "IFTYPE_AP changed");
static_assert(LDN_LKL_WL_IFTYPE_MONITOR == LKL_WL_IFTYPE_MONITOR, "IFTYPE_MONITOR changed");
static_assert(LDN_LKL_WL_ANY_WIPHY      == LKL_WL_ANY_WIPHY,      "ANY_WIPHY changed");
static_assert(LDN_LKL_WL_SSID_MAX       == LKL_WL_SSID_MAX,       "SSID_MAX changed");

static_assert(LDN_LKL_WL_EV_CONNECT                == LKL_WL_EV_CONNECT,   "EV_CONNECT changed");
static_assert(LDN_LKL_WL_EV_CONTROL_PORT           == LKL_WL_EV_CONTROL_PORT, "EV_CONTROL_PORT changed");
static_assert(LDN_LKL_WL_EV_FRAME                  == LKL_WL_EV_FRAME,     "EV_FRAME changed");
static_assert(LDN_LKL_WL_EV_DEL_STATION            == LKL_WL_EV_DEL_STATION, "EV_DEL_STATION changed");
static_assert(LDN_LKL_WL_EV_CONTROL_PORT_TX_STATUS == LKL_WL_EV_CONTROL_PORT_TX_STATUS,
			  "EV_CONTROL_PORT_TX_STATUS changed");
static_assert(LDN_LKL_WL_EV_SCAN_DONE              == LKL_WL_EV_SCAN_DONE, "EV_SCAN_DONE changed");

i32 ldn_lkl_wl_find_wiphy(void *ctx, const char *name, u32 *wiphy) {
	UNUSED(ctx);
	return lkl_wl_find_wiphy(name, wiphy);
}

i32 ldn_lkl_wl_list_ifaces(void *ctx, u32 wiphy, LdnLklWlIface *out, i32 cap) {
	UNUSED(ctx);
	return lkl_wl_list_ifaces(wiphy, (struct lkl_wl_iface *) out, cap);
}

i32 ldn_lkl_wl_new_iface(void *ctx, u32 wiphy, const char *name, u32 iftype,
						 i32 monitor_other_bss, LdnLklWlIface *out) {
	UNUSED(ctx);
	return lkl_wl_new_iface(wiphy, name, iftype, monitor_other_bss,
							(struct lkl_wl_iface *) out);
}

i32 ldn_lkl_wl_del_iface(void *ctx, i32 ifindex) {
	UNUSED(ctx);
	return lkl_wl_del_iface(ifindex);
}

i32 ldn_lkl_wl_set_channel(void *ctx, i32 ifindex, u32 freq) {
	UNUSED(ctx);
	return lkl_wl_set_channel(ifindex, freq);
}

i32 ldn_lkl_wl_trigger_scan(void *ctx, i32 ifindex, const unsigned char *ssid, i32 ssid_len,
							u32 freq) {
	UNUSED(ctx);
	return lkl_wl_trigger_scan(ifindex, ssid, ssid_len, freq);
}

i32 ldn_lkl_wl_list_bss(void *ctx, i32 ifindex, LdnLklWlBss *out, i32 cap) {
	UNUSED(ctx);
	return lkl_wl_list_bss(ifindex, (struct lkl_wl_bss *) out, cap);
}

i32 ldn_lkl_wl_connect(void *ctx, i32 ifindex, const unsigned char *ssid, i32 ssid_len,
					   u32 freq, const unsigned char *key, i32 key_len) {
	UNUSED(ctx);
	return lkl_wl_connect(ifindex, ssid, ssid_len, freq, key, key_len);
}

i32 ldn_lkl_wl_disconnect(void *ctx, i32 ifindex) {
	UNUSED(ctx);
	return lkl_wl_disconnect(ifindex);
}

i32 ldn_lkl_wl_start_ap(void *ctx, i32 ifindex, const unsigned char *ssid, i32 ssid_len,
						u32 freq, const void *head, i32 head_len, const void *tail,
						i32 tail_len, u32 beacon_interval, u32 dtim_period) {
	UNUSED(ctx);
	return lkl_wl_start_ap(ifindex, ssid, ssid_len, freq, head, head_len, tail, tail_len,
						   beacon_interval, dtim_period);
}

i32 ldn_lkl_wl_stop_ap(void *ctx, i32 ifindex) {
	UNUSED(ctx);
	return lkl_wl_stop_ap(ifindex);
}

i32 ldn_lkl_wl_add_key(void *ctx, i32 ifindex, i32 idx, const void *key, i32 key_len,
					   const unsigned char *mac) {
	UNUSED(ctx);
	return lkl_wl_add_key(ifindex, idx, key, key_len, mac);
}

i32 ldn_lkl_wl_set_default_key(void *ctx, i32 ifindex, i32 idx, i32 multicast) {
	UNUSED(ctx);
	return lkl_wl_set_default_key(ifindex, idx, multicast);
}

i32 ldn_lkl_wl_add_station(void *ctx, i32 ifindex, const unsigned char *mac, u32 aid,
						   u32 listen_interval, u32 capability, const void *rates,
						   i32 rates_len) {
	UNUSED(ctx);
	return lkl_wl_add_station(ifindex, mac, aid, listen_interval, capability, rates,
							  rates_len);
}

i32 ldn_lkl_wl_set_station_authorized(void *ctx, i32 ifindex, const unsigned char *mac) {
	UNUSED(ctx);
	return lkl_wl_set_station_authorized(ifindex, mac);
}

i32 ldn_lkl_wl_del_station(void *ctx, i32 ifindex, const unsigned char *mac) {
	UNUSED(ctx);
	return lkl_wl_del_station(ifindex, mac);
}

i32 ldn_lkl_wl_get_station(void *ctx, i32 ifindex, unsigned char *mac) {
	UNUSED(ctx);
	return lkl_wl_get_station(ifindex, mac);
}

i32 ldn_lkl_wl_register_frame(void *ctx, i32 ifindex, u32 frame_type) {
	UNUSED(ctx);
	return lkl_wl_register_frame(ifindex, frame_type);
}

i32 ldn_lkl_wl_tx_frame(void *ctx, i32 ifindex, const void *frame, i32 len) {
	UNUSED(ctx);
	return lkl_wl_tx_frame(ifindex, frame, len);
}

i32 ldn_lkl_wl_tx_control_port(void *ctx, i32 ifindex, const unsigned char *mac,
							   const void *frame, i32 len) {
	UNUSED(ctx);
	return lkl_wl_tx_control_port(ifindex, mac, frame, len);
}

i32 ldn_lkl_wl_next_event(void *ctx, LdnLklWlEvent *ev, void *buf, i32 cap, u32 timeout_ms) {
	UNUSED(ctx);
	return lkl_wl_next_event((struct lkl_wl_event *) ev, buf, cap, timeout_ms);
}

void ldn_lkl_wl_release(void *ctx) {
	UNUSED(ctx);
	lkl_wl_release();
}

i32 ldn_lkl_cleanup(void *ctx) {
	ldn_lkl_wl_release(ctx);
	ldn_lkl_usb_detach(ctx);
	lkl_cleanup();
	free(ctx);
	return 0;
}

i32 ldn_lkl_is_running(void *ctx) {
	UNUSED(ctx);
	return lkl_is_running();
}

const char *ldn_lkl_strerror(i32 err) { return lkl_strerror(err); }
