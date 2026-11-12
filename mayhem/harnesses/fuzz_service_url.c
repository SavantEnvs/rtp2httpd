/* Service URL constructors (src/service.c): /udp/ /rtp/ /rtsp/ /http/ request paths and direct URLs. */
#include "service.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return -1;
  uint8_t kind = data[0];
  data++;
  size--;

  char *url = malloc(size + 1);
  if (!url)
    return 0;
  memcpy(url, data, size);
  url[size] = '\0';

  service_t *s = NULL;
  switch (kind & 3) {
  case 0:
    s = service_create_from_udpxy_url(url);
    break;
  case 1:
    s = service_create_from_rtsp_url(url);
    break;
  case 2:
    s = service_create_from_rtp_url(url);
    break;
  default:
    s = service_create_from_http_url(url);
    break;
  }
  if (s) {
    service_t *c = service_clone(s);
    service_free(c);
    service_free(s);
  }

  /* Seek-parameter extraction edits the query string in place. */
  char *q = strchr(url, '?');
  if (q) {
    char *name = NULL, *value = NULL;
    int bo = 0, eo = 0, tze = 0, tzo = 0, win = 0;
    seek_mode_t mode = SEEK_MODE_PASSTHROUGH;
    if (service_extract_seek_params(q, &name, &value, &bo, &eo, &mode, &tze, &tzo, &win) == 0) {
      free(name);
      free(value);
    }
  }

  free(url);
  return 0;
}
