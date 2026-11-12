# `fec_process_packet`: FEC slot index trusted from a later packet, not from the group's `m`

- **Where:** `src/rtp_fec.c:295` (`grp->fec_slots[redund_idx].received`), after `fec_find_or_create_group()`.
- **Cause:** a group is looked up by `(begin_seq, end_seq)` only. Its `fec_slots` array is allocated once, with the
  `m` of the first FEC packet seen. A later packet for the same range with a larger `redund_num` and a
  `redund_idx` beyond that first `m` passes the `redund_idx >= m` check (against its own `m`) and then indexes
  past the end of the first packet's array.
- **Impact:** an out-of-bounds read and then write (`data`/`data_len`/`received`) of heap memory, from two FEC
  datagrams on the RTP or FEC multicast socket. Reached by `fec_process_packet()` exactly as `stream.c` calls it.
- **Reproducer:** `crash.bin` is in the harness input format (a flags byte, then 2-byte little-endian length
  framed datagrams): two FEC packets for seq 10..10, `m=1 idx=0` then `m=255 idx=200`. Run it with
  `mayhem/fuzz_rtp_payload-standalone crash.bin` (ASan: heap-buffer-overflow in `fec_process_packet`).
- **Fix:** in `fec_find_or_create_group()` also match on `m` (or store the group's `m` and reject a packet
  whose `redund_num` differs), and check `redund_idx < grp->m` before indexing.
