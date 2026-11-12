/* RTP datagram pipeline (src/rtp.c, rtp_reorder.c, rtp_fec.c, rs_fec.c).
 *
 * The input is a stream of UDP datagrams, each framed as a 2-byte little-endian length plus that many bytes;
 * byte 0 selects the reorder window (1 = the large FEC-sized window). Every datagram goes through
 * rtp_get_payload() like stream.c does, then:
 *   - type 1 (RTP): rtp_reorder_insert() on a no-FEC reorder context (deliver callback instead of a client
 *     connection), and the packet is kept in a second window that the FEC context reads recovery data from,
 *     as flush_consecutive() does when FEC is enabled;
 *   - type 2 (FEC): fec_process_packet(), then fec_attempt_recovery() for the hole at base_seq (Reed-Solomon
 *     decode), as rtp_reorder_insert() does on a gap.
 * rtp_reorder_insert() itself is not given the FEC context: its recovery delivery needs a live client
 * connection (send queue, worker buffer pools), which has no in-process stand-in. */
#include "buffer_pool.h"
#include "rtp_fec.h"
#include "rtp_reorder.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int rtp_get_payload(uint8_t *buf, int recv_len, uint8_t **payload, int *size, uint16_t *seqn);

#define MAX_DATAGRAMS 512

static int sink_deliver(void *arg, buffer_ref_t *buf) {
  volatile uint8_t sink = 0;
  const uint8_t *p = (const uint8_t *)buf->data + buf->data_offset;
  for (size_t i = 0; i < buf->data_size; i++)
    sink ^= p[i];
  (void)sink;
  (*(size_t *)arg)++;
  return (int)buf->data_size;
}

/* Keep a packet in the FEC window the way flush_consecutive() keeps it when FEC is enabled. */
static void fec_window_store(rtp_reorder_t *w, buffer_ref_t *ref, uint16_t seq) {
  int slot = seq & w->window_mask;
  if (w->slots[slot])
    buffer_ref_put(w->slots[slot]);
  buffer_ref_get(ref);
  w->slots[slot] = ref;
  w->seq[slot] = seq;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return -1;
  int use_fec_window = data[0] & 1;
  data++;
  size--;

  static buffer_pool_t pool;
  static int pool_ready;
  if (!pool_ready) {
    if (buffer_pool_init(&pool, BUFFER_POOL_BUFFER_SIZE, 64, 4096, 64, 8, 4096) < 0)
      return 0;
    pool_ready = 1;
  }

  size_t delivered = 0;
  rtp_reorder_t plain, fecwin;
  fec_context_t fec;
  if (rtp_reorder_init(&plain, 0) < 0)
    return 0;
  if (rtp_reorder_init(&fecwin, use_fec_window) < 0) {
    rtp_reorder_cleanup(&plain);
    return 0;
  }
  plain.deliver = sink_deliver;
  plain.deliver_arg = &delivered;
  fec_init(&fec, 0, &fecwin);

  int fec_seen_first = 0;
  for (int n = 0; n < MAX_DATAGRAMS && size >= 2; n++) {
    size_t len = (size_t)data[0] | ((size_t)data[1] << 8);
    data += 2;
    size -= 2;
    if (len > size)
      len = size;

    uint8_t *buf = malloc(len ? len : 1);
    if (!buf)
      break;
    if (len)
      memcpy(buf, data, len);
    data += len;
    size -= len;

    uint8_t *payload = NULL;
    int payload_size = 0;
    uint16_t seqn = 0;
    int rc = rtp_get_payload(buf, (int)len, &payload, &payload_size, &seqn);

    if (rc >= 0) {
      /* The returned window must stay inside the datagram; read it all so ASan sees any overrun. */
      if (payload < buf || payload_size < 0 || (size_t)(payload - buf) + (size_t)payload_size > len)
        abort();
      volatile uint8_t sink = 0;
      for (int i = 0; i < payload_size; i++)
        sink ^= payload[i];
      (void)sink;
    }

    if (rc == 2) {
      fec_process_packet(&fec, payload, payload_size);
    } else if (rc == 1 && len <= BUFFER_POOL_BUFFER_SIZE) {
      buffer_ref_t *ref = buffer_pool_alloc_from(&pool);
      if (ref) {
        memcpy(ref->data, buf, len);
        ref->data_offset = (size_t)(payload - buf);
        ref->data_size = (size_t)payload_size;

        rtp_reorder_insert(&plain, ref, seqn, NULL, 0, NULL);

        if (!fec_seen_first) {
          fecwin.base_seq = seqn;
          fec_seen_first = 1;
        }
        if ((int16_t)(seqn - fecwin.base_seq) >= 0)
          fec_window_store(&fecwin, ref, seqn);
        while (rtp_reorder_get(&fecwin, fecwin.base_seq))
          fecwin.base_seq++;
        if (fec.min_end_seq_valid && (int16_t)(fecwin.base_seq - fec.min_end_seq) > 0)
          fec_release_expired_groups(&fec, fecwin.base_seq);
        buffer_ref_put(ref);
      }
    }

    if (fec_seen_first && fec.groups && !rtp_reorder_get(&fecwin, fecwin.base_seq)) {
      uint8_t *rec = NULL;
      int rec_len = 0;
      if (fec_attempt_recovery(&fec, fecwin.base_seq, &rec, &rec_len) == 0) {
        volatile uint8_t sink = 0;
        for (int i = 0; i < rec_len; i++)
          sink ^= rec[i];
        (void)sink;
        free(rec);
        fecwin.base_seq++;
      }
    }

    free(buf);
  }

  fec_cleanup(&fec, -1);
  rtp_reorder_cleanup(&fecwin);
  rtp_reorder_cleanup(&plain);
  return 0;
}
