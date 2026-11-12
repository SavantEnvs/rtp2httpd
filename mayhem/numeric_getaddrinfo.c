/* Keeps fuzz runs off the network: service.c resolves hostnames from input with getaddrinfo(), which would
 * query DNS. Force numeric-only resolution; everything else is the real libc call. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stddef.h>

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
  static int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
  if (!real)
    real = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
  struct addrinfo h = {0};
  if (hints)
    h = *hints;
  h.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  return real(node, service, &h, res);
}
