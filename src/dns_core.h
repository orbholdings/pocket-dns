#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Shared by the firmware and the native regression tests; no Arduino dependency.
namespace pocketdns {
constexpr int HASH_BYTES = 5;
constexpr uint64_t HASH_MASK = (1ULL << 40) - 1;
constexpr int INDEX_ENTRIES = 4096;
constexpr int MAX_RANGE = 256;

inline uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; ++i) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; ++k) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; ++k) { b[k] = (uint8_t)h; h >>= 8; }
}

template<class Reader>
bool indexedContains(uint64_t h, uint32_t count,
                     const uint8_t index[INDEX_ENTRIES][HASH_BYTES],
                     uint8_t* scratch, Reader read) {
  if (!count || h < unpackHash(index[0]) || h > unpackHash(index[INDEX_ENTRIES - 1])) return false;
  int lo = 0, hi = INDEX_ENTRIES - 2, segment = 0;
  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    uint64_t value = unpackHash(index[mid]);
    if (value == h) return true;
    if (value < h) { segment = mid; lo = mid + 1; } else hi = mid - 1;
  }
  uint32_t first = (uint64_t)segment * (count - 1) / (INDEX_ENTRIES - 1);
  uint32_t last = (uint64_t)(segment + 1) * (count - 1) / (INDEX_ENTRIES - 1);
  uint32_t length = last - first + 1;
  if (length <= MAX_RANGE) {
    size_t bytes = length * HASH_BYTES;
    if (!read(first * HASH_BYTES, scratch, bytes)) return false;
    for (uint32_t i = 0; i < length; ++i) {
      uint64_t value = unpackHash(scratch + i * HASH_BYTES);
      if (value == h) return true;
      if (value > h) break;
    }
    return false;
  }
  // Large S3 lists must search the entire bucket, rather than truncate it.
  while (first <= last) {
    uint32_t mid = first + (last - first) / 2;
    if (!read(mid * HASH_BYTES, scratch, HASH_BYTES)) return false;
    uint64_t value = unpackHash(scratch);
    if (value == h) return true;
    if (value < h) first = mid + 1;
    else { if (!mid) break; last = mid - 1; }
  }
  return false;
}

inline bool validDomain(const char* d) {
  size_t n = strlen(d);
  if (n < 3 || n > 253 || !strchr(d, '.')) return false;
  size_t label = 0;
  for (size_t i = 0; i < n; ++i) {
    char c = d[i];
    if (c == '.') { if (!label || d[i - 1] == '-') return false; label = 0; continue; }
    if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_') return false;
    if (!label && c == '-') return false;
    if (++label > 63) return false;
  }
  return label && d[n - 1] != '-';
}
inline bool domainMatches(const char* query, const char* rule) {
  size_t q = strlen(query), r = strlen(rule);
  return q >= r && strcmp(query + q - r, rule) == 0 && (q == r || query[q - r - 1] == '.');
}

// Standard UDP DNS queries with a single uncompressed question, Internet class.
inline size_t parseQuery(const uint8_t* pkt, size_t len, char* out,
                         uint16_t* qtype, int* qend) {
  if (len < 17 || (pkt[2] & 0xF8) || pkt[4] != 0 || pkt[5] != 1 ||
      pkt[6] || pkt[7] || pkt[8] || pkt[9]) return 0;
  size_t i = 12, o = 0;
  bool terminated = false;
  while (i < len) {
    uint8_t label = pkt[i++];
    if (!label) { terminated = true; break; }
    if (label > 63 || i + label > len || o + label + (o ? 1 : 0) > 253) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < label; ++k) {
      uint8_t c = pkt[i++];
      if (c < 33 || c > 126 || c == '.') return 0;
      out[o++] = (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
    }
  }
  if (!terminated || i + 4 > len || pkt[i + 2] != 0 || pkt[i + 3] != 1) return 0;
  if (!o) out[o++] = '.';
  out[o] = 0; *qtype = ((uint16_t)pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  return o;
}
inline int buildError(uint8_t* pkt, uint8_t rcode) {
  pkt[2] = 0x80 | (pkt[2] & 1); pkt[3] = 0x80 | (rcode & 15);
  memset(pkt + 4, 0, 8);
  return 12;
}
inline int buildBlocked(uint8_t* pkt, int qend, uint16_t qtype) {
  pkt[2] = 0x80 | (pkt[2] & 1); pkt[3] = 0x80 | (pkt[3] & 0x10);
  memset(pkt + 6, 0, 6);
  if (qtype != 1 && qtype != 28) return qend; // NODATA for other record types.
  pkt[7] = 1;
  uint8_t* a = pkt + qend;
  const uint8_t prefix[] = {0xc0, 0x0c, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0};
  memcpy(a, prefix, sizeof(prefix)); a[3] = (uint8_t)qtype;
  size_t bytes = qtype == 1 ? 4 : 16;
  a[11] = bytes; memset(a + 12, 0, bytes);
  return qend + 12 + bytes;
}
}
