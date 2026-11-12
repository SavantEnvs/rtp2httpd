/* Incremental HTTP/1.1 chunked transfer-encoding decoder (src/http_chunked_decoder.c). */
#include "http_chunked_decoder.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int emit_cb(void *opaque, const uint8_t *data, size_t len) {
  size_t *total = opaque;
  volatile uint8_t sink = 0;
  for (size_t i = 0; i < len; i++)
    sink ^= data[i];
  (void)sink;
  *total += len;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return -1;

  /* First byte selects how the stream is cut into recv()-sized pieces. */
  size_t piece = (size_t)data[0] + 1;
  data++;
  size--;

  http_chunked_decoder_t dec;
  http_chunked_decoder_init(&dec);
  size_t emitted = 0;
  size_t off = 0;
  http_chunked_decode_result_t rc = HTTP_CHUNKED_DECODE_NEED_MORE;

  while (off < size && rc == HTTP_CHUNKED_DECODE_NEED_MORE) {
    size_t n = size - off < piece ? size - off : piece;
    uint8_t *copy = malloc(n);
    if (!copy)
      return 0;
    memcpy(copy, data + off, n);
    size_t consumed = 0;
    rc = http_chunked_decoder_feed(&dec, copy, n, emit_cb, &emitted, &consumed);
    free(copy);
    if (consumed > n)
      abort();
    off += n;
  }
  (void)http_chunked_decoder_finish(&dec);
  return 0;
}
