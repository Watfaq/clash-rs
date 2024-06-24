#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ERR_OK 0

#define ERR_START 1

#define ERR_CONFIG 2

typedef struct ConfigOverride {
  int32_t tun_fd;
  uint16_t http_port;
  const char *dns_server;
  const char *bind_address;
  const char *external_controller;
} ConfigOverride;

typedef struct GeneralConfig {
  uint16_t port;
  uint16_t socks_port;
  uint16_t mixed_port;
  const char *secret;
  bool tun_enabled;
  bool dns_enabled;
  bool ipv6_enabled;
} GeneralConfig;

const char *get_last_error(void);

int start_clash_with_config(const char *cfg_dir,
                            const char *cfg_str,
                            const char *log_file,
                            const struct ConfigOverride *cfg_override);

bool shutdown_clash(void);

int parse_general_config(const char *cfg_str, struct GeneralConfig *general);

char *parse_proxy_list(const char *cfg_str);

void free_string(char *ptr);

char *parse_proxy_group(const char *cfg_str);

char *parse_rule_list(const char *cfg_str);
