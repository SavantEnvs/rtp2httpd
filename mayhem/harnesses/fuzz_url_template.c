/* Catch-up URL templating and seek-value parsing (src/url_template.c, src/service.c). */
#include "service.h"
#include "url_template.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Layout: 4 control bytes, seek value '\0' url template. */
  if (size < 4)
    return -1;
  int begin_off = (int8_t)data[0] * 60;
  int end_off = (int8_t)data[1] * 60;
  seek_mode_t mode = (data[2] & 1) ? SEEK_MODE_RANGE : SEEK_MODE_PASSTHROUGH;
  int tz_explicit = (data[2] >> 1) & 1;
  int tz_off = ((int)(data[3] & 0x7f) - 64) * 900;
  data += 4;
  size -= 4;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  const char *seek = buf;
  char *sep = memchr(buf, '\0', size);
  const char *url = sep ? sep + 1 : buf + size;

  seek_parse_result_t pr;
  memset(&pr, 0, sizeof(pr));
  if (service_parse_seek_value(seek, begin_off, end_off, "Mozilla/5.0", mode, tz_explicit, tz_off, 3600, &pr) == 0) {
    char out[512];
    (void)service_convert_seek_value(&pr, out, sizeof(out));
    (void)service_format_recent_seek_range(&pr, out, sizeof(out));
    char resolved[1024];
    (void)url_template_resolve(url, &pr, resolved, sizeof(resolved));
  }

  url_template_analysis_t an;
  memset(&an, 0, sizeof(an));
  (void)url_template_analyze(url, &an);
  (void)url_template_has_placeholders(url);

  free(buf);
  return 0;
}
