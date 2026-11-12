# `http_parse_url_components` overruns the 1024-byte `path` buffer in `m3u.c`

- **Where:** `src/m3u.c:231` (`get_server_address`) passes `char path[1024]`; `src/http.c:932` does
  `strncpy(path, path_start, 2047); path[2047] = '\0';` and `src/http.h` documents `path` as "at least 2048 bytes".
- **Cause:** `strncpy` pads with NULs up to `n`, so any `config.hostname` that contains a path
  (for example the documented `https://example.org/prefix`, or just `/`) writes 2048 bytes into the 1024-byte stack buffer.
- **Impact:** stack buffer overflow (ASan: `stack-buffer-overflow ... WRITE of size 2047 in strncpy`) whenever a
  hostname with a path is configured and an M3U playlist is generated. Zero bytes only, but it smashes the
  caller's frame.
- **Fix:** declare `char path[2048]` in `m3u.c`, or bound the copy to the caller's size.
- **Reproducing:** `repro.c` (link against the instrumented project objects); the fuzz harness itself uses
  the documented 2048-byte buffer so it can explore the parser beyond this immediate crash.
