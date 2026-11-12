/* HLS/M3U playlist rewriter for the HTTP reverse proxy (src/http_proxy_rewrite.c). */
#include "http_proxy_rewrite.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Layout: 2-byte upstream port, upstream path '\0' base url '\0' playlist body. */
  if (size < 2)
    return -1;
  int port = data[0] | (data[1] << 8);
  data += 2;
  size -= 2;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  const char *path = buf;
  char *p = memchr(buf, '\0', size);
  const char *base = p ? p + 1 : buf + size;
  const char *body = base;
  if (p && (size_t)(p - buf) < size) {
    char *q = memchr(p + 1, '\0', size - (size_t)(p - buf) - 1);
    body = q ? q + 1 : buf + size;
  }

  rewrite_context_t ctx = {
      .upstream_host = "upstream.example",
      .upstream_port = port,
      .upstream_path = path,
      .base_url = base,
  };

  char *out = NULL;
  size_t out_size = 0;
  if (rewrite_m3u_content(&ctx, body, &out, &out_size) == 0 && out) {
    if (strlen(out) != out_size)
      abort();
    free(out);
  }

  char resolved[512];
  (void)rewrite_resolve_relative_url(body, "upstream.example", port, path, resolved, sizeof(resolved));
  (void)rewrite_url_to_proxy_format(&ctx, body, resolved, sizeof(resolved));

  free(buf);
  return 0;
}
