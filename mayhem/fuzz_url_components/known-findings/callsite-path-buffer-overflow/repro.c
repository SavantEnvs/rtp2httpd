/* Mirrors src/m3u.c get_server_address(): config.hostname is parsed into a 1024-byte path buffer.
 * Build against the project sources with ASan, e.g. from the repo root:
 *   clang -fsanitize=address -g -Isrc -D_GNU_SOURCE mayhem/fuzz_url_components/known-findings/callsite-path-buffer-overflow/repro.c \
 *         src/http.c ... (or link against build-fuzz/libproject.a plus -lm -lpthread -lrt)
 */
#include "http.h"
int main(void) {
  char protocol[16] = {0}, host[256] = {0}, port[16] = {0};
  char path[1024] = {0}; /* m3u.c:231 */
  return http_parse_url_components("https://example.org/prefix", protocol, host, port, path);
}
