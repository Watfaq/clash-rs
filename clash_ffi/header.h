#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ERR_OK 0

#define ERR_START 1

#define ERR_CONFIG 2

typedef struct ConfigOverride {
  int32_t tun_fd;
  const char *dns_server;
  const char *bind_address;
} ConfigOverride;

typedef struct GeneralConfig {
  uint16_t port;
  uint16_t socks_port;
  uint16_t mixed_port;
  bool tun_enabled;
  bool dns_enabled;
  bool ipv6_enabled;
} GeneralConfig;

const char *get_last_error(void);

int start_clash_with_config(const char *cfg_dir,
                            const char *cfg_str,
                            const struct ConfigOverride *cfg_override);

int parse_general_config(const char *cfg_str, struct GeneralConfig *general);
