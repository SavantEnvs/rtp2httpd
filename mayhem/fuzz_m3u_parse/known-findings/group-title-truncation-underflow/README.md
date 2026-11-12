# `m3u_parse_and_create_services`: group-title truncation underflows for long names

- **Where:** `src/m3u.c:1219` (`current_extinf.group_title[max_group_len] = '\0'`).
- **Cause:** when `group_len + 1 + base_len >= 256`, `max_group_len = sizeof(name) - base_len - 2` is computed
  in `size_t`. `base_name` is capped at 255 bytes, so a 255-byte channel name makes it wrap to `SIZE_MAX`
  and the NUL is written at `group_title[-1]`, one byte before the array.
- **Impact:** a one-byte NUL out-of-bounds write (in the preceding `name` field of the struct), reachable from any
  external M3U playlist (a remote server's response) with a 255-byte channel name and a `group-title`.
- **Reproducer:** `crash.m3u`, run with `mayhem/fuzz_m3u_parse-standalone crash.m3u`
  (UBSan: `index 18446744073709551615 out of bounds for type 'char[256]'`).
- **Fix:** clamp first, e.g. `if (base_len + 2 >= sizeof(name)) max_group_len = 0; else max_group_len = sizeof(name) - base_len - 2;`
  (and truncate `base_name` as well).
