/* M3U playlist loader (src/m3u.c): #EXTINF attributes, catchup sources, service creation, transformed playlist. */
#include "epg.h"
#include "m3u.h"
#include "service.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  service_hashmap_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Playlists reach the parser as one NUL-terminated string (inline config or fetched body). */
  char *content = malloc(size + 1);
  if (!content)
    return 0;
  memcpy(content, data, size);
  content[size] = '\0';

  (void)m3u_parse_and_create_services(content, "inline");
  (void)m3u_get_transformed_playlist();
  char *playlist = m3u_generate_playlist("router.lan:5140", NULL, NULL);
  free(playlist);

  /* Per-input isolation: drop every service, the transformed playlist and the EPG URL the parse left behind. */
  service_free_all();
  m3u_reset_transformed_playlist();
  epg_cleanup();

  free(content);
  return 0;
}
