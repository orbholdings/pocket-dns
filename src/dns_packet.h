#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <algorithm>
#include "dns_core.h"

namespace pdns {
constexpr size_t PACKET_MAX = 4096;
constexpr size_t CACHE_PACKET_MAX = 1024;
constexpr size_t CACHE_SLOTS = 12;
constexpr size_t MAX_TTLS = 32;

inline uint16_t u16(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }
inline uint32_t u32(const uint8_t* p) { return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]; }
inline void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
inline void put32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

// Bounded compression-pointer traversal. The wire offset follows the original name,
// while pointer traversal is limited independently to avoid cycles and long chains.
inline bool name(const uint8_t* p, size_t n, size_t& wire, char* out = nullptr, bool* compressed = nullptr) {
  size_t pos = wire, after = 0, used = 0;
  bool jumped = false;
  for (unsigned hops = 0; hops < 128; ++hops) {
    if (pos >= n) return false;
    uint8_t count = p[pos++];
    if ((count & 0xc0) == 0xc0) {
      if (compressed) *compressed = true;
      if (pos >= n) return false;
      size_t dest = ((count & 0x3f) << 8) | p[pos++];
      if (dest < 12 || dest >= n) return false;
      if (!jumped) after = pos;
      jumped = true; pos = dest;
      continue;
    }
    if (count & 0xc0 || count > 63) return false;
    if (!count) {
      wire = jumped ? after : pos;
      if (out) { if (!used) out[used++] = '.'; out[used] = 0; }
      return true;
    }
    if (pos + count > n || used + count + (used ? 1 : 0) > 253) return false;
    if (used) { if (out) out[used] = '.'; ++used; }
    for (unsigned k = 0; k < count; ++k) {
      uint8_t c = p[pos++];
      if (c < 33 || c > 126 || c == '.') return false;
      if (out) out[used] = c >= 'A' && c <= 'Z' ? c + 32 : c;
      ++used;
    }
  }
  return false;
}

struct Question {
  char domain[254]{};
  uint16_t type = 0, klass = 1, end = 0, udpLimit = 512;
  uint8_t keyFlags = 0;
  bool cacheable = true, compressed = false;
};

inline bool question(const uint8_t* p, size_t n, Question& q, bool response = false) {
  q = Question{};
  if (n < 17 || n > PACKET_MAX || u16(p + 4) != 1 || (p[2] & 0x78)) return false;
  if (bool(p[2] & 0x80) != response) return false;
  size_t pos = 12;
  if (!name(p, n, pos, q.domain, &q.compressed) || pos + 4 > n) return false;
  q.type = u16(p + pos); q.klass = u16(p + pos + 2); q.end = pos + 4;
  if (q.klass != 1) return false;
  q.keyFlags = (p[2] & 1) | (p[3] & 0x30); // RD, CD and the client's AD request.
  if (response) return true;
  if (u16(p + 6) || u16(p + 8)) return false;
  pos = q.end;
  uint16_t additional = u16(p + 10);
  if (additional > 4) return false;
  bool opt = false;
  for (unsigned i = 0; i < additional; ++i) {
    if (!name(p, n, pos) || pos + 10 > n) return false;
    uint16_t type = u16(p + pos), klass = u16(p + pos + 2), bytes = u16(p + pos + 8);
    uint32_t ttl = u32(p + pos + 4); pos += 10;
    if (pos + bytes > n) return false;
    if (type == 41) {
      if (opt || ((ttl >> 16) & 0xff)) return false;
      opt = true;
      q.udpLimit = std::min<uint16_t>(PACKET_MAX, std::max<uint16_t>(512, klass));
      if (ttl & 0x8000) q.keyFlags |= 0x40; // DNSSEC OK is a separate cache key bit.
      // Cookies, ECS and other option-specific replies must never be shared across clients.
      if (bytes || (ttl >> 24)) q.cacheable = false;
    } else q.cacheable = false;
    pos += bytes;
  }
  return pos == n;
}

inline bool validResponse(const uint8_t* p,size_t n) {
  Question q;if(!question(p,n,q,true))return false;
  if(p[2]&2)return true; // A truncated UDP response is retried over TCP.
  uint32_t answers=u16(p+6),authority=u16(p+8),additional=u16(p+10);
  uint32_t count=answers+authority+additional;if(count>256)return false;
  size_t pos=q.end;
  for(uint32_t i=0;i<count;i++) {
    if(!name(p,n,pos)||pos+10>n)return false;
    uint16_t type=u16(p+pos),bytes=u16(p+pos+8);size_t start=pos+10,end=start+bytes;if(end>n)return false;
    if(type==1&&bytes!=4)return false;if(type==28&&bytes!=16)return false;
    if(type==2||type==5||type==12||type==39){size_t r=start;if(!name(p,n,r)||r!=end)return false;}
    if(type==6){size_t r=start;if(!name(p,n,r)||!name(p,n,r)||r+20!=end)return false;}
    pos=end;
  }
  return pos==n;
}

inline bool sameQuestion(const Question& a, const Question& b) {
  return a.type == b.type && a.klass == b.klass && strcmp(a.domain, b.domain) == 0;
}

inline size_t error(uint8_t* p, size_t n, uint8_t code) {
  if (n < 12) return 0;
  Question q;
  bool have = question(p, n, q);
  uint8_t rd = p[2] & 1, cd = p[3] & 0x10;
  p[2] = 0x80 | rd; p[3] = 0x80 | cd | (code & 15);
  memset(p + 6, 0, 6);
  if (have && !q.compressed) { put16(p + 4, 1); return q.end; }
  memset(p + 4, 0, 8); return 12;
}

inline size_t makeQuery(const char*,uint16_t,uint16_t,uint8_t*,size_t);
inline size_t sinkhole(uint8_t* p, size_t n, const Question& q, uint32_t ipv4 = 0) {
  // Canonicalise compressed client questions before using the standard 0xc00c pointer.
  size_t end = q.end;
  if(q.compressed){uint16_t id=u16(p);uint8_t rd=p[2]&1,cd=p[3]&0x10;end=makeQuery(q.domain,q.type,id,p,PACKET_MAX);if(!end)return error(p,n,1);p[2]=rd;p[3]=cd;}
  p[2] = 0x80 | (p[2] & 1); p[3] = 0x80 | (p[3] & 0x10);
  memset(p + 6, 0, 6);
  if (q.type != 1 && q.type != 28) return end;
  put16(p + 6, 1);
  uint8_t* a = p + end;
  put16(a, 0xc00c); put16(a + 2, q.type); put16(a + 4, 1); put32(a + 6, 60);
  uint16_t bytes = q.type == 1 ? 4 : 16; put16(a + 10, bytes);
  memset(a + 12, 0, bytes);
  if (q.type == 1 && ipv4) memcpy(a + 12, &ipv4, 4);
  return end + 12 + bytes;
}

inline size_t truncated(uint8_t* output, const uint8_t* request, size_t len) {
  memcpy(output, request, len);
  size_t n = error(output, len, 0);
  output[2] |= 2;
  return n;
}

inline size_t makeQuery(const char* domain, uint16_t type, uint16_t id, uint8_t* out, size_t cap) {
  if (cap < 18) return 0;
  memset(out, 0, 12); put16(out, id); out[2] = 1; out[5] = 1;
  size_t pos = 12; const char* start = domain;
  while (*start) {
    const char* dot = strchr(start, '.');
    size_t length = dot ? size_t(dot - start) : strlen(start);
    if (!length || length > 63 || pos + length + 6 > cap) return 0;
    out[pos++] = length; memcpy(out + pos, start, length); pos += length;
    if (!dot) break; start = dot + 1;
  }
  out[pos++] = 0; put16(out + pos, type); put16(out + pos + 2, 1); return pos + 4;
}

struct TtlMap {
  uint16_t offsets[MAX_TTLS]{};
  uint8_t count = 0;
  uint32_t lifetime = 0;
  bool negative = false;
};

inline bool cacheTtls(const uint8_t* p, size_t n, TtlMap& map) {
  map = TtlMap{};
  Question q;
  if (!question(p, n, q, true) || q.compressed || (p[2] & 2) || n > CACHE_PACKET_MAX) return false;
  uint8_t rcode = p[3] & 15;
  if (rcode != 0 && rcode != 3) return false;
  uint32_t minimum = 300, negativeTtl = 0;
  bool soa = false, anyAnswer = false;
  uint32_t records = uint32_t(u16(p + 6)) + u16(p + 8) + u16(p + 10);
  if (!records || records > MAX_TTLS + 1) return false;
  size_t pos = q.end;
  for (uint32_t i = 0; i < records; ++i) {
    if (!name(p, n, pos) || pos + 10 > n) return false;
    uint16_t type = u16(p + pos), bytes = u16(p + pos + 8);
    if(i<u16(p+6)&&(type==q.type||q.type==255))anyAnswer=true;
    uint32_t ttl = u32(p + pos + 4); size_t start = pos + 10, end = start + bytes;
    if (end > n) return false;
    if (type == 41) { if (bytes || (ttl >> 16)) return false; }
    else {
      if (!ttl || map.count == MAX_TTLS || type == 250) return false;
      map.offsets[map.count++] = pos + 4; minimum = std::min(minimum, ttl);
      if (type == 6) {
        size_t r = start;
        if (!name(p, n, r) || !name(p, n, r) || r + 20 != end) return false;
        negativeTtl = std::min(ttl, u32(p + r + 16)); soa = true;
      }
    }
    pos = end;
  }
  if (pos != n || !map.count) return false;
  if (rcode == 3 || !anyAnswer) {
    if (!soa || !negativeTtl) return false;
    map.negative = true;
    minimum = std::min(minimum, negativeTtl);
  }
  map.lifetime = minimum; return minimum > 0;
}

class AnswerCache {
  struct Entry {
    uint8_t packet[CACHE_PACKET_MAX]{};
    char domain[254]{};
    TtlMap ttls{};
    uint32_t made = 0, touched = 0;
    uint16_t bytes = 0, type = 0;
    uint8_t flags = 0;
  } entries_[CACHE_SLOTS];
public:
  uint32_t hits = 0, misses = 0;
  void clear() { for (auto& e : entries_) e.bytes = 0; }
  bool get(const Question& q, const uint8_t* request, size_t requestLen, uint32_t now, uint8_t* out, size_t& length) {
    if (!q.cacheable || q.compressed) { ++misses; return false; }
    for (auto& e : entries_) {
      if (!e.bytes) continue;
      uint32_t age = uint32_t(now - e.made) / 1000;
      if (age >= e.ttls.lifetime) { e.bytes = 0; continue; }
      if (e.type != q.type || e.flags != q.keyFlags || strcmp(e.domain, q.domain)) continue;
      Question response;
      if (!question(e.packet, e.bytes, response, true) || response.end != q.end || requestLen < q.end) continue;
      memcpy(out, e.packet, e.bytes); memcpy(out, request, 2);
      memcpy(out + 12, request + 12, q.end - 12);
      for (unsigned i = 0; i < e.ttls.count; ++i) {
        unsigned offset = e.ttls.offsets[i];
        uint32_t value = u32(e.packet + offset);
        put32(out + offset, value > age ? value - age : 0);
      }
      e.touched = now; length = e.bytes; ++hits; return true;
    }
    ++misses; return false;
  }
  bool put(const Question& q, const uint8_t* response, size_t len, uint32_t now) {
    if (!q.cacheable || q.compressed) return false;
    TtlMap ttl;
    if (!cacheTtls(response, len, ttl)) return false;
    Question rq;
    if (!question(response, len, rq, true) || !sameQuestion(q, rq) || q.end != rq.end) return false;
    Entry* target = &entries_[0];
    for (auto& e : entries_) {
      if (!e.bytes || uint32_t(now - e.made) / 1000 >= e.ttls.lifetime) { target = &e; break; }
      if (uint32_t(now - e.touched) > uint32_t(now - target->touched)) target = &e;
    }
    memcpy(target->packet, response, len); strcpy(target->domain, q.domain);
    if(ttl.negative)for(unsigned i=0;i<ttl.count;i++){
      unsigned offset=ttl.offsets[i];
      if(u16(target->packet+offset-4)==6)put32(target->packet+offset,std::min(u32(target->packet+offset),ttl.lifetime));
    }
    target->ttls = ttl; target->made = target->touched = now;
    target->bytes = len; target->type = q.type; target->flags = q.keyFlags;
    return true;
  }
  size_t count(uint32_t now) const {
    size_t result = 0;
    for (const auto& e : entries_) if (e.bytes && uint32_t(now - e.made) / 1000 < e.ttls.lifetime) ++result;
    return result;
  }
};
}
