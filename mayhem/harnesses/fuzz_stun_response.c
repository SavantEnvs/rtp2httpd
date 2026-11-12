/* STUN Binding response parser (src/stun.c), used for RTSP UDP NAT traversal. */
#include "stun.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Transaction id of the (never sent) request this response is matched against. */
  static const unsigned char txid[STUN_TRANSACTION_ID_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                                               0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  stun_state_t state;
  memset(&state, 0, sizeof(state));
  memcpy(state.transaction_id, txid, sizeof(txid));
  state.in_progress = 1;

  (void)stun_is_stun_packet(data, size);
  int rc = stun_parse_response(&state, data, size);
  if (rc == 0) {
    (void)stun_get_mapped_port(&state);
    (void)stun_get_mapped_ipv4(&state);
  }
  return 0;
}
