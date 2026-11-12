/* Known-answer checks over rtp2httpd's parsers, built with the project's normal flags (no sanitizers).
 * Prints "SELFTEST total=N passed=P failed=F" last; mayhem/test.sh reads that line. */
#include "connection.h"
#include "http.h"
#include "http_chunked_decoder.h"
#include "http_proxy_rewrite.h"
#include "m3u.h"
#include "rtp.h"
#include "service.h"
#include "stun.h"
#include "url_template.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int total, passed;

#define CHECK(cond, name)                                                                                              \
  do {                                                                                                                 \
    total++;                                                                                                           \
    if (cond) {                                                                                                        \
      passed++;                                                                                                        \
      printf("ok   %s\n", name);                                                                                       \
    } else {                                                                                                           \
      printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__);                                                           \
    }                                                                                                                  \
  } while (0)

static int str_eq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static void test_rtp(void) {
  uint8_t pkt[17] = {0x80, 33, 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 2, 'A', 'B', 'C', 'D', 'E'};
  uint8_t *payload = NULL;
  int size = 0;
  uint16_t seq = 0;
  int rc = rtp_get_payload(pkt, sizeof(pkt), &payload, &size, &seq);
  CHECK(rc == 1 && payload == pkt + 12 && size == 5 && seq == 0x1234 && memcmp(payload, "ABCDE", 5) == 0,
        "rtp: plain packet payload window and sequence number");

  uint8_t csrc[25] = {0x82, 33, 0x00, 0x07, 0, 0, 0, 1, 0, 0, 0, 2};
  memcpy(csrc + 20, "HELLO", 5);
  rc = rtp_get_payload(csrc, sizeof(csrc), &payload, &size, &seq);
  CHECK(rc == 1 && payload == csrc + 20 && size == 5 && seq == 7, "rtp: two CSRC entries shift the payload by 8 bytes");

  uint8_t trunc[14] = {0x8f, 33, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 'A', 'B'};
  rc = rtp_get_payload(trunc, sizeof(trunc), &payload, &size, &seq);
  CHECK(rc == -1, "rtp: CSRC count beyond the datagram is rejected");
}

typedef struct {
  char buf[256];
  size_t len;
} sink_t;

static int collect(void *opaque, const uint8_t *data, size_t len) {
  sink_t *s = opaque;
  if (s->len + len >= sizeof(s->buf))
    return -1;
  memcpy(s->buf + s->len, data, len);
  s->len += len;
  s->buf[s->len] = '\0';
  return 0;
}

static void test_chunked(void) {
  static const char body[] = "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
  sink_t s = {{0}, 0};
  http_chunked_decoder_t d;
  http_chunked_decoder_init(&d);
  size_t used = 0;
  http_chunked_decode_result_t rc =
      http_chunked_decoder_feed(&d, (const uint8_t *)body, sizeof(body) - 1, collect, &s, &used);
  CHECK(rc == HTTP_CHUNKED_DECODE_DONE && used == sizeof(body) - 1 && str_eq(s.buf, "hello world"),
        "chunked: two chunks and a terminator decode to 'hello world'");

  sink_t s2 = {{0}, 0};
  http_chunked_decoder_init(&d);
  rc = HTTP_CHUNKED_DECODE_NEED_MORE;
  for (size_t i = 0; i < sizeof(body) - 1; i++) {
    size_t c = 0;
    rc = http_chunked_decoder_feed(&d, (const uint8_t *)body + i, 1, collect, &s2, &c);
    if (rc == HTTP_CHUNKED_DECODE_ERROR)
      break;
  }
  CHECK(rc == HTTP_CHUNKED_DECODE_DONE && str_eq(s2.buf, "hello world"), "chunked: byte-at-a-time feed gives the same result");

  const char bad[] = "zz\r\n";
  sink_t s3 = {{0}, 0};
  http_chunked_decoder_init(&d);
  rc = http_chunked_decoder_feed(&d, (const uint8_t *)bad, sizeof(bad) - 1, collect, &s3, &used);
  CHECK(rc == HTTP_CHUNKED_DECODE_ERROR && s3.len == 0, "chunked: non-hex chunk size is an error");
}

static void test_stun(void) {
  stun_state_t st;
  memset(&st, 0, sizeof(st));
  for (int i = 0; i < STUN_TRANSACTION_ID_SIZE; i++)
    st.transaction_id[i] = (unsigned char)(i + 1);
  /* XOR-MAPPED-ADDRESS 203.0.113.9:54321 */
  uint8_t resp[32] = {0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                      0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xf5, 0x23, 0xea, 0x12, 0xd5, 0x4b};
  CHECK(stun_is_stun_packet(resp, sizeof(resp)) != 0, "stun: binding response is recognised as STUN");
  int rc = stun_parse_response(&st, resp, sizeof(resp));
  char ip[INET_ADDRSTRLEN] = "";
  struct in_addr a = stun_get_mapped_ipv4(&st);
  inet_ntop(AF_INET, &a, ip, sizeof(ip));
  CHECK(rc == 0 && stun_get_mapped_port(&st) == 54321 && str_eq(ip, "203.0.113.9"), "stun: XOR-MAPPED-ADDRESS decodes to 203.0.113.9:54321");

  memset(&st, 0, sizeof(st));
  rc = stun_parse_response(&st, resp, sizeof(resp));
  CHECK(rc == -1 && stun_get_mapped_port(&st) == 0, "stun: wrong transaction id is rejected");
}

static void test_http(void) {
  static const char req[] = "GET /udp/239.1.1.1:5000?fcc=1.2.3.4:15970 HTTP/1.1\r\nHost: router.lan:5140\r\n"
                            "User-Agent: VLC\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n";
  char *in = calloc(1, INBUF_SIZE);
  memcpy(in, req, sizeof(req) - 1);
  int n = (int)sizeof(req) - 1;
  http_request_t r;
  http_request_init(&r);
  int rc = http_parse_request(in, &n, &r);
  CHECK(rc == 1 && n == 0 && str_eq(r.method, "GET") && str_eq(r.url, "/udp/239.1.1.1:5000?fcc=1.2.3.4:15970") &&
            str_eq(r.hostname, "router.lan:5140") && str_eq(r.user_agent, "VLC") && str_eq(r.x_forwarded_for, "1.2.3.4"),
        "http: request line and headers are parsed");
  http_request_cleanup(&r);
  free(in);

  char dec[] = "a%20b%2Fc+d";
  http_url_decode(dec);
  CHECK(str_eq(dec, "a b/c+d"), "http: percent-decoding leaves '+' alone");

  char v[64];
  int q = http_parse_query_param("x=1&r2h-token=abc%20d&y=2", "r2h-token", v, sizeof(v));
  CHECK(q == 0 && str_eq(v, "abc d"), "http: query parameter lookup with decoding");

  char proto[16], host[256], port[16], path[2048];
  rc = http_parse_url_components("https://example.org:8443/prefix", proto, host, port, path);
  CHECK(rc == 0 && str_eq(proto, "https") && str_eq(host, "example.org") && str_eq(port, "8443") && str_eq(path, "/prefix"),
        "http: URL split into protocol, host, port and path");
}

static void test_service(void) {
  service_t *s = service_create_from_udpxy_url("/udp/239.1.1.1:5000?fcc=1.2.3.4:15970");
  CHECK(s && s->service_type == SERVICE_MRTP && str_eq(s->rtp_url, "rtp://239.1.1.1:5000?fcc=1.2.3.4:15970"),
        "service: /udp/ URL becomes an RTP multicast service");
  if (s)
    service_free(s);

  s = service_create_from_udpxy_url("/rtsp/10.0.0.50:554/ch1?playseek=20240101120000-20240101130000&x=1");
  CHECK(s && s->service_type == SERVICE_RTSP && str_eq(s->rtsp_url, "rtsp://10.0.0.50:554/ch1?x=1") &&
            str_eq(s->seek_param_name, "playseek") && str_eq(s->seek_param_value, "20240101120000-20240101130000"),
        "service: /rtsp/ URL splits the playseek parameter off");
  if (s)
    service_free(s);

  CHECK(service_create_from_udpxy_url("/nope/1.2.3.4:5") == NULL, "service: unknown scheme is rejected");
}

static void test_seek(void) {
  seek_parse_result_t sp;
  memset(&sp, 0, sizeof(sp));
  int rc = service_parse_seek_value("20240101120000-20240101130000", 0, 0, "", SEEK_MODE_PASSTHROUGH, 1, 8 * 3600, 3600, &sp);
  CHECK(rc == 0 && sp.has_seek && sp.begin_utc == 1704110400 && sp.end_utc == 1704114000,
        "seek: playseek range parses to epoch 1704110400..1704114000");

  char res[512];
  rc = url_template_resolve("rtsp://h/c?playseek={utc:YmdHMS}-{utcend:YmdHMS}", &sp, res, sizeof(res));
  CHECK(rc == 0 && str_eq(res, "rtsp://h/c?playseek=20240101120000-20240101130000"), "template: {utc}/{utcend} placeholders are filled");

  url_template_analysis_t an;
  memset(&an, 0, sizeof(an));
  rc = url_template_analyze("rtsp://h/c?playseek={utc:YmdHMS}-{utcend:YmdHMS}", &an);
  CHECK(rc == 0 && an.has_template && an.needs_begin && an.needs_end && str_eq(an.seek_param_name, "playseek"),
        "template: analysis finds begin/end placeholders and the seek parameter name");
}

static void test_m3u(void) {
  rewrite_context_t ctx = {"up.example", 8080, "/live/index.m3u8", "http://router:5140/"};
  char *out = NULL;
  size_t out_size = 0;
  int rc = rewrite_m3u_content(&ctx, "#EXTM3U\n#EXTINF:4,\nseg1.ts\nhttp://other.example/x/seg2.ts\n/abs/seg3.ts\n", &out, &out_size);
  CHECK(rc == 0 && out &&
            strstr(out, "\nhttp://router:5140/http/up.example:8080/live/seg1.ts\n") &&
            strstr(out, "\nhttp://router:5140/http/other.example/x/seg2.ts\n") &&
            strstr(out, "\nhttp://router:5140/http/up.example:8080/abs/seg3.ts\n") && strncmp(out, "#EXTM3U\n#EXTINF:4,\n", 19) == 0,
        "m3u rewrite: relative, absolute and root-relative segment URLs go through the proxy");
  free(out);

  service_hashmap_init();
  rc = m3u_parse_and_create_services("#EXTM3U\n#EXTINF:-1 tvg-id=\"c1\" group-title=\"News\",CCTV-1\nrtp://239.1.1.1:5000\n"
                                     "#EXTINF:-1,Two\nrtsp://10.0.0.50:554/ch2\n",
                                     "inline");
  int rtp_ok = services && services->service_type == SERVICE_MRTP && str_eq(services->rtp_url, "rtp://239.1.1.1:5000");
  int rtsp_ok = services && services->next && services->next->service_type == SERVICE_RTSP &&
                str_eq(services->next->rtsp_url, "rtsp://10.0.0.50:554/ch2");
  CHECK(rc == 0 && rtp_ok && rtsp_ok, "m3u: playlist entries become RTP and RTSP services");
  char *pl = m3u_generate_playlist("router.lan:5140", NULL, NULL);
  CHECK(pl && strstr(pl, "#EXTINF:-1 tvg-id=\"c1\" group-title=\"News\",CCTV-1\nhttp://router.lan:5140/News/CCTV-1\n") &&
            strstr(pl, "#EXTINF:-1,Two\nhttp://router.lan:5140/Two\n"),
        "m3u: generated playlist points channels at this server by name");
  free(pl);
  service_free_all();
}

int main(void) {
  test_rtp();
  test_chunked();
  test_stun();
  test_http();
  test_service();
  test_seek();
  test_m3u();
  printf("SELFTEST total=%d passed=%d failed=%d\n", total, passed, total - passed);
  return passed == total ? 0 : 1;
}
