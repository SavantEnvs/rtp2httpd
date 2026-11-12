/* Configured-hostname handling (src/http.c, src/utils.c). The input is up to four '\n'-separated strings:
 * config.hostname, the request Host header, X-Forwarded-Host and X-Forwarded-Proto. The hostname goes through
 * http_parse_url_components() with the buffer sizes documented in its http.h contract (protocol 16, host 256,
 * port 16, path 2048), then through its consumers: the Host-header check (connection.c), IPv6 re-bracketing
 * (format_host_for_url) and the proxy base-URL builder (utils.c build_proxy_base_url). */
#include "configuration.h"
#include "http.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Copy the next '\n'-terminated field of *p (bounded by end) into a new NUL-terminated string. */
static char *next_field(const char **p, const char *end) {
  const char *s = *p;
  const char *nl = memchr(s, '\n', (size_t)(end - s));
  size_t n = nl ? (size_t)(nl - s) : (size_t)(end - s);
  char *f = malloc(n + 1);
  if (!f)
    return NULL;
  memcpy(f, s, n);
  f[n] = '\0';
  *p = nl ? nl + 1 : end;
  return f;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *p = (const char *)data;
  const char *end = p + size;
  char *url = next_field(&p, end);
  char *host_header = next_field(&p, end);
  char *xfh = next_field(&p, end);
  char *xfp = next_field(&p, end);
  if (!url || !host_header || !xfh || !xfp)
    goto out;

  /* NB: m3u.c get_server_address() passes a 1024-byte path buffer instead of the documented 2048 and overflows
   * it on every URL with a path; see mayhem/fuzz_url_components/known-findings/. */
  char protocol[16] = {0};
  char host[256] = {0};
  char port[16] = {0};
  char path[2048] = {0};
  (void)http_parse_url_components(url, protocol, host, port, path);

  /* connection.c: only protocol and host are requested, then the Host header is matched against the host. */
  char protocol2[16] = {0};
  char expected_host[256] = {0};
  if (http_parse_url_components(url, protocol2, expected_host, NULL, NULL) == 0)
    (void)http_match_host_header(host_header, expected_host);

  /* m3u.c: a parsed host is re-bracketed before it is embedded in a URL. */
  char host_formatted[300];
  (void)format_host_for_url(host, host_formatted, sizeof(host_formatted));

  /* utils.c: with a Host (or X-Forwarded-Host) the base URL is built from config.hostname's protocol and the
   * headers. An empty host would fall back to get_server_address(), whose 1024-byte path buffer is the known
   * finding, so that fallback is left to the repro. */
  config.hostname = url;
  config.xff = (size > 0 && (data[0] & 1));
  config.app_path_prefix = NULL;
  config.use_relative_path_in_m3u = 0;
  if (host_header[0] || (config.xff && xfh[0])) {
    char *base = build_proxy_base_url(host_header, xfh, xfp);
    free(base);
  }
  config.hostname = NULL;
  config.xff = 0;

out:
  free(url);
  free(host_header);
  free(xfh);
  free(xfp);
  return 0;
}
