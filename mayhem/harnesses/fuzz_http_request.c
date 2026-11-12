/* HTTP request parser (src/http.c): picohttpparser request line + headers, body, query params, URL decoding. */
#include "connection.h"
#include "http.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* connection.c hands the parser at most INBUF_SIZE buffered bytes. */
  if (size > INBUF_SIZE)
    return -1;

  char *inbuf = malloc(INBUF_SIZE);
  if (!inbuf)
    return 0;
  memcpy(inbuf, data, size);
  int in_len = (int)size;

  http_request_t req;
  http_request_init(&req);
  int rc = http_parse_request(inbuf, &in_len, &req);
  if (in_len < 0 || (size_t)in_len > size)
    abort();

  if (rc >= 0) {
    static const char *const params[] = {"r2h-token", "fcc", "fcc-type", "playseek", "r2h-seek-name", "tvgurl"};
    char value[256];
    const char *query = strchr(req.url, '?');
    if (query) {
      for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++)
        (void)http_parse_query_param(query + 1, params[i], value, sizeof(value));
    }
    /* The body is NUL-terminated only once the request is complete (rc == 1), as connection.c relies on. */
    if (rc == 1 && req.body)
      (void)http_parse_query_param(req.body, "r2h-token", value, sizeof(value));

    char decoded[HTTP_URL_BUFFER_SIZE];
    memcpy(decoded, req.url, sizeof(decoded));
    decoded[sizeof(decoded) - 1] = '\0';
    (void)http_url_decode(decoded);
  }

  http_request_cleanup(&req);
  free(inbuf);
  return 0;
}
