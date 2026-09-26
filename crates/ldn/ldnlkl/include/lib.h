#ifndef LIB_H_
#define LIB_H_

#include <stdint.h>

typedef enum {
	LDN_LKL_USB_DRIVER_NONE = 0,
	LDN_LKL_USB_DRIVER_UNKNOWN,
	LDN_LKL_USB_DRIVER_WIFI,
	LDN_LKL_USB_DRIVER_ETHERNET,
} LdnLklUsbDriverType;

// Implemented by consumer
extern void impl_ldn_lkl_print(const char *str, int32_t len, void *userdata);
extern int impl_ldn_lkl_load_firmware(const char *name, void **dest, long long unsigned int *size, void *userdata);

int32_t ldn_lkl_init(void **ctx, void* userdata, const char *cmdline);

void ldn_lkl_find_driver(void *ctx, int32_t vid, int32_t pid, void (*callback)(const char *fw, void *userdata), void *userdata);

LdnLklUsbDriverType ldn_lkl_get_driver_type(void *ctx, int32_t vid, int32_t pid, const char **name);

#define LDN_LKL_AF_NETLINK        16
#define LDN_LKL_AF_PACKET         17
#define LDN_LKL_SOCK_DGRAM         2
#define LDN_LKL_SOCK_RAW           3
#define LDN_LKL_SOL_NETLINK      270
#define LDN_LKL_NETLINK_ROUTE      0
#define LDN_LKL_NETLINK_GENERIC   16
#define LDN_LKL_NETLINK_CAP_ACK   10
#define LDN_LKL_NETLINK_EXT_ACK   11
#define LDN_LKL_ETH_P_ALL     0x0003
#define LDN_LKL_EAGAIN            11
#define LDN_LKL_EINTR              4

int32_t ldn_lkl_socket(void *ctx, int32_t domain, int32_t type, int32_t protocol);
int32_t ldn_lkl_open_netlink(void *ctx, int32_t family);
int32_t ldn_lkl_open_packet(void *ctx, uint16_t eth_protocol);
int32_t ldn_lkl_bind(void *ctx, int32_t fd, const void *addr, int32_t addrlen);
int32_t ldn_lkl_setsockopt(void *ctx, int32_t fd, int32_t level, int32_t optname, const void *value, int32_t len);
int32_t ldn_lkl_setsockopt_int(void *ctx, int32_t fd, int32_t level, int32_t optname, int32_t value);
int32_t ldn_lkl_set_recv_timeout_ms(void *ctx, int32_t fd, uint32_t timeout_ms);
int32_t ldn_lkl_getsockname(void *ctx, int32_t fd, void *addr, int32_t *addrlen);
int32_t ldn_lkl_netlink_pid(void *ctx, int32_t fd, uint32_t *pid);
int64_t ldn_lkl_sendto(void *ctx, int32_t fd, const void *buf, int32_t len, int32_t flags, const void *dest, int32_t destlen);
int64_t ldn_lkl_recvfrom(void *ctx, int32_t fd, void *buf, int32_t len, int32_t flags, void *addr, int32_t *addrlen);
int32_t ldn_lkl_close(void *ctx, int32_t fd);
int32_t ldn_lkl_set_nonblock(void *ctx, int32_t fd);

int32_t ldn_lkl_sockaddr_nl(void *buf, int32_t cap, uint32_t pid, uint32_t groups);
int32_t ldn_lkl_sockaddr_ll(void *buf, int32_t cap, uint16_t eth_protocol, int32_t ifindex);
int32_t ldn_lkl_sockaddr_in(void *buf, int32_t cap, uint32_t addr, uint16_t port);
int32_t ldn_lkl_sockaddr_in_parse(const void *buf, int32_t len, uint32_t *addr, uint16_t *port);

int32_t ldn_lkl_ifname_to_ifindex(void *ctx, const char *name);
int32_t ldn_lkl_if_up(void *ctx, int32_t ifindex);
int32_t ldn_lkl_if_down(void *ctx, int32_t ifindex);
int32_t ldn_lkl_if_set_mtu(void *ctx, int32_t ifindex, int32_t mtu);

#define LDN_LKL_AF_INET            2
#define LDN_LKL_AF_INET6          10

int32_t ldn_lkl_if_add_ip(void *ctx, int32_t ifindex, int32_t af, const void *addr, uint32_t prefix_len);
int32_t ldn_lkl_if_del_ip(void *ctx, int32_t ifindex, int32_t af, const void *addr, uint32_t prefix_len);
int32_t ldn_lkl_add_neighbor(void *ctx, int32_t ifindex, int32_t af, const void *addr, const void *mac);
int32_t ldn_lkl_sysctl(void *ctx, const char *path, const char *value);

typedef struct {
	void *  (*submit_control)(void *cookie, const unsigned char *setup, void *data, int32_t len);
	void *  (*submit_transfer)(void *cookie, unsigned char ep, void *data, int32_t len);
	int32_t (*poll)(void *cookie, void *handle, int32_t *result);
	void    (*cancel)(void *cookie, void *handle);
	void    (*release)(void *cookie, void *handle);
	int32_t (*set_alt)(void *cookie, unsigned char iface, unsigned char alt);

	void *cookie;
	int32_t superspeed; /* bcdUSB >= 0x0300 */
} LdnLklUsbOps;

int32_t ldn_lkl_usb_attach(void *ctx, const LdnLklUsbOps *ops);
int32_t ldn_lkl_usb_detach(void *ctx);
int32_t ldn_lkl_usb_completion_irq(void *ctx);
void ldn_lkl_trigger_irq(void *ctx, int32_t irq);

#define LDN_LKL_WL_IFTYPE_STATION   2
#define LDN_LKL_WL_IFTYPE_AP        3
#define LDN_LKL_WL_IFTYPE_MONITOR   6

#define LDN_LKL_WL_ANY_WIPHY        0xffffffffu

#define LDN_LKL_WL_EV_CONNECT                   1
#define LDN_LKL_WL_EV_CONTROL_PORT              2
#define LDN_LKL_WL_EV_FRAME                     3
#define LDN_LKL_WL_EV_DEL_STATION               4
#define LDN_LKL_WL_EV_CONTROL_PORT_TX_STATUS    5
#define LDN_LKL_WL_EV_SCAN_DONE                 6

#define LDN_LKL_WL_SSID_MAX        32

typedef struct {
	int32_t index;
	uint32_t wiphy;
	uint32_t iftype;
	unsigned char mac[6];
	char name[16];
} LdnLklWlIface;

typedef struct {
	unsigned char bssid[6];
	uint32_t freq;
	uint32_t ssid_len;
	unsigned char ssid[LDN_LKL_WL_SSID_MAX];
} LdnLklWlBss;

typedef struct {
	uint32_t type;
	int32_t ifindex;
	unsigned char mac[6];
	uint16_t status;
	uint32_t freq;
	uint32_t acked;
	uint32_t len;
	uint32_t lost;
} LdnLklWlEvent;

int32_t ldn_lkl_wl_find_wiphy(void *ctx, const char *name, uint32_t *wiphy);
int32_t ldn_lkl_wl_list_ifaces(void *ctx, uint32_t wiphy, LdnLklWlIface *out, int32_t cap);
int32_t ldn_lkl_wl_new_iface(void *ctx, uint32_t wiphy, const char *name, uint32_t iftype,
                             int32_t monitor_other_bss, LdnLklWlIface *out);
int32_t ldn_lkl_wl_del_iface(void *ctx, int32_t ifindex);
int32_t ldn_lkl_wl_set_channel(void *ctx, int32_t ifindex, uint32_t freq);

int32_t ldn_lkl_wl_trigger_scan(void *ctx, int32_t ifindex, const unsigned char *ssid,
                                int32_t ssid_len, uint32_t freq);
int32_t ldn_lkl_wl_list_bss(void *ctx, int32_t ifindex, LdnLklWlBss *out, int32_t cap);

int32_t ldn_lkl_wl_connect(void *ctx, int32_t ifindex, const unsigned char *ssid,
                           int32_t ssid_len, uint32_t freq, const unsigned char *key,
                           int32_t key_len);
int32_t ldn_lkl_wl_disconnect(void *ctx, int32_t ifindex);

int32_t ldn_lkl_wl_start_ap(void *ctx, int32_t ifindex, const unsigned char *ssid,
                            int32_t ssid_len, uint32_t freq,
                            const void *head, int32_t head_len,
                            const void *tail, int32_t tail_len,
                            uint32_t beacon_interval, uint32_t dtim_period);
int32_t ldn_lkl_wl_stop_ap(void *ctx, int32_t ifindex);

int32_t ldn_lkl_wl_add_key(void *ctx, int32_t ifindex, int32_t idx, const void *key,
                           int32_t key_len, const unsigned char *mac);
int32_t ldn_lkl_wl_set_default_key(void *ctx, int32_t ifindex, int32_t idx, int32_t multicast);

int32_t ldn_lkl_wl_add_station(void *ctx, int32_t ifindex, const unsigned char *mac,
                               uint32_t aid, uint32_t listen_interval, uint32_t capability,
                               const void *rates, int32_t rates_len);
int32_t ldn_lkl_wl_set_station_authorized(void *ctx, int32_t ifindex, const unsigned char *mac);
int32_t ldn_lkl_wl_del_station(void *ctx, int32_t ifindex, const unsigned char *mac);
int32_t ldn_lkl_wl_get_station(void *ctx, int32_t ifindex, unsigned char *mac);

int32_t ldn_lkl_wl_register_frame(void *ctx, int32_t ifindex, uint32_t frame_type);
int32_t ldn_lkl_wl_tx_frame(void *ctx, int32_t ifindex, const void *frame, int32_t len);
int32_t ldn_lkl_wl_tx_control_port(void *ctx, int32_t ifindex, const unsigned char *mac,
                                   const void *frame, int32_t len);

int32_t ldn_lkl_wl_next_event(void *ctx, LdnLklWlEvent *ev, void *buf, int32_t cap,
                              uint32_t timeout_ms);
void ldn_lkl_wl_release(void *ctx);

int32_t ldn_lkl_cleanup(void *ctx);
int32_t ldn_lkl_is_running(void *ctx);
const char *ldn_lkl_strerror(int32_t err);

#endif
