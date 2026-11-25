#include "../../include/cyw43.h"

#include <string.h>

#include "pico/cyw43_arch.h"
#include "lwip/dhcp.h"
#include "lwip/netif.h"

int
CYW43_CONST_link_down(void)
{
  return CYW43_LINK_DOWN;
}

int
CYW43_CONST_link_join(void)
{
  return CYW43_LINK_JOIN;
}

int
CYW43_CONST_link_noip(void)
{
  return CYW43_LINK_NOIP;
}

int
CYW43_CONST_link_up(void)
{
  return CYW43_LINK_UP;
}

int
CYW43_CONST_link_fail(void)
{
  return CYW43_LINK_FAIL;
}

int
CYW43_CONST_link_nonet(void)
{
  return CYW43_LINK_NONET;
}

int
CYW43_CONST_link_badauth(void)
{
  return CYW43_LINK_BADAUTH;
}

int
CYW43_tcpip_link_status(void)
{
  return cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
}

bool
CYW43_dhcp_supplied(void)
{
  struct netif *netif = &cyw43_state.netif[CYW43_ITF_STA];
  return dhcp_supplied_address(netif);
}

/* Last CYW43_arch_init_with_country failure, for post-mortem from Ruby
 * (CYW43._init_error): a pico_error_codes value from cyw43_arch_init, or
 * CYW43_INIT_ERR_LED_PROBE when init succeeded but the WL-GPIO LED
 * loopback probe read back 0. 0 = no error recorded. */
#define CYW43_INIT_ERR_LED_PROBE (-1000)
static int cyw43_init_last_error = 0;

int
CYW43_init_last_error(void)
{
  return cyw43_init_last_error;
}

/* Driver-state peek for bring-up debugging (CYW43._state):
 * [initialized, itf_state bitmask, wifi_join_state, poll hook armed] */
void
CYW43_debug_state(int out[4])
{
  out[0] = cyw43_is_initialized(&cyw43_state) ? 1 : 0;
  out[1] = (int)cyw43_state.itf_state;
  out[2] = (int)cyw43_state.wifi_join_state;
  out[3] = (cyw43_poll != NULL) ? 1 : 0;
}

/* Force the lazy chip bring-up (cyw43_ensure_up: WL_REG_ON power cycle,
 * PIO-SPI bus init, firmware upload) and surface its error code, which
 * the void cyw43_arch_* wrappers otherwise swallow. cyw43_gpio_set is
 * the smallest public entry point that runs ensure_up first. */
int
CYW43_probe_up(void)
{
  return cyw43_gpio_set(&cyw43_state, 0, false);
}

int
CYW43_arch_init_with_country(const uint8_t *country)
{
  int res;
  if (country == NULL) {
    res = cyw43_arch_init();
  } else {
    res = cyw43_arch_init_with_country(CYW43_COUNTRY(country[0], country[1], 0));
  }
  if (res != 0) {
    cyw43_init_last_error = res;
    return res; // error
  }
  // Historically this probed for a CYW43 by writing the WL LED GPIO and
  // reading it back. cyw43_arch_init() succeeding already proves the chip
  // is present (the firmware upload handshakes over PIO-SPI and fails on
  // a chipless board), so a readback mismatch is recorded as a warning in
  // cyw43_init_last_error but no longer fails the init. Observed on
  // Pico 2 W under PICO_CYW43_ARCH_POLL: "ccgpioin" reads back 0 for the
  // LED output even though init and the LED itself work.
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
#if PICO_CYW43_ARCH_POLL
  // Poll mode: pump the driver while we wait, as the background IRQ would
  absolute_time_t deadline = make_timeout_time_ms(5);
  while (!time_reached(deadline)) {
    cyw43_arch_poll();
  }
#else
  sleep_ms(5);
#endif
  if (cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN) == 1) {
    cyw43_init_last_error = 0;
  } else {
    cyw43_init_last_error = CYW43_INIT_ERR_LED_PROBE; // warning only
  }
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
  return 0;
}

void
CYW43_arch_deinit(void)
{
  cyw43_arch_deinit();
}

void
CYW43_arch_enable_sta_mode(void)
{
  cyw43_arch_enable_sta_mode();
#if PICO_CYW43_ARCH_POLL
  /* Poll mode services the chip less promptly than the background IRQ;
   * the default power-save PM then misses beacons and flaps the link
   * (join succeeds, lease acquired, association drops seconds later).
   * Performance PM is the standard poll-mode remedy. */
  cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);
#endif
}

void
CYW43_arch_disable_sta_mode(void)
{
  cyw43_arch_disable_sta_mode();
}

/* Response shape of CYW43_IOCTL_GET_SSID (wlc_ssid_t; cyw43_ll.h defines
 * only the ioctl number). */
typedef struct {
  uint32_t ssid_len;
  uint8_t ssid[32];
} cyw43_wlc_ssid_t;

static bool
sta_associated_ssid_matches(const char *want)
{
  cyw43_wlc_ssid_t resp = {0};
  if (cyw43_ioctl(&cyw43_state, CYW43_IOCTL_GET_SSID, sizeof(resp), (uint8_t *)&resp, CYW43_ITF_STA) != 0) {
    return false;
  }
  size_t want_len = strlen(want);
  return resp.ssid_len == want_len && memcmp(resp.ssid, want, want_len) == 0;
}

int
CYW43_wifi_connect_with_dhcp(const char *ssid, const char *pw, uint32_t auth, uint32_t timeout_ms)
{
  int result = cyw43_arch_wifi_connect_timeout_ms(ssid, pw, auth, timeout_ms);
  if (result == 0 && !sta_associated_ssid_matches(ssid)) {
    /* A join that timed out on a PREVIOUS call keeps running in the
     * firmware (the SDK's connect loop abandons it without aborting), and
     * survives leave/re-up via the firmware's auto-rejoin of the stored
     * SSID. The SDK's success poll checks link status only — never which
     * network — so without this check the call reports success while
     * associated to the wrong SSID. */
    result = PICO_ERROR_CONNECT_FAILED;
  }
  cyw43_init_last_error = result; /* pico_error_codes; readable via CYW43._init_error */
  if (result == 0) {
    struct netif *netif = &cyw43_state.netif[CYW43_ITF_STA];
    if (!dhcp_supplied_address(netif)) {
      dhcp_set_struct(netif, &cyw43_state.dhcp_client);
      dhcp_start(netif);
    }
  }
  else {
    /* Abort whatever join is still in flight (or wrongly completed) so it
     * cannot outlive this call and leak into a later connect. */
    cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  }
  return result;
}

int
CYW43_wifi_disconnect(void)
{
  struct netif *netif = &cyw43_state.netif[CYW43_ITF_STA];
  dhcp_release_and_stop(netif);
  int result = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  return result;
}

void
CYW43_GPIO_write(uint8_t pin, uint8_t val)
{
  cyw43_arch_gpio_put(pin, val == 1);
}

uint8_t
CYW43_GPIO_read(uint8_t pin)
{
  return(cyw43_arch_gpio_get(pin) ? 1 : 0);
}

const char *
CYW43_ipv4_address(char *buf, size_t buflen)
{
  const char *res;
  lwip_begin();
  const ip4_addr_t *ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_STA]);
  if (ip && ip->addr != 0) {
    res = ipaddr_ntoa_r(ip, buf, buflen);
  } else {
    res = NULL;
  }
  lwip_end();
  return res;
}

const char *
CYW43_ipv4_netmask(char *buf, size_t buflen)
{
  const char *res;
  lwip_begin();
  const ip4_addr_t *netmask = netif_ip4_netmask(&cyw43_state.netif[CYW43_ITF_STA]);
  if (netmask && netmask->addr != 0) {
    res = ipaddr_ntoa_r(netmask, buf, buflen);
  } else {
    res = NULL;
  }
  lwip_end();
  return res;
}

const char *
CYW43_ipv4_gateway(char *buf, size_t buflen)
{
  const char *res;
  lwip_begin();
  const ip4_addr_t *gateway = netif_ip4_gw(&cyw43_state.netif[CYW43_ITF_STA]);
  if (gateway && gateway->addr != 0) {
    res = ipaddr_ntoa_r(gateway, buf, buflen);
  } else {
    res = NULL;
  }
  lwip_end();
  return res;
}
