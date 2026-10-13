#include "../src/dns_core.h"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <random>
#include <vector>
using namespace pocketdns;

std::vector<uint8_t> question(uint16_t type = 1) {
  std::vector<uint8_t> p{0x12,0x34,1,0,0,1,0,0,0,0,0,1,
    3,'W','W','W',7,'E','x','a','m','p','l','e',3,'c','o','m',0,
    0,(uint8_t)type,0,1};
  // EDNS OPT must be removed from sinkhole responses.
  p.insert(p.end(), {0,0,41,4,208,0,0,0,0,0,0});
  return p;
}
void wireTests() {
  char name[256]{}; uint16_t type = 0; int end = 0;
  auto q = question(); size_t len = q.size(); q.resize(512, 0xaa);
  assert(parseQuery(q.data(), len, name, &type, &end) == 15);
  assert(strcmp(name, "www.example.com") == 0 && type == 1 && end == 33);
  int n = buildBlocked(q.data(), end, type);
  assert(n == end + 16 && q[0] == 0x12 && q[1] == 0x34);
  assert(q[2] == 0x81 && q[7] == 1 && q[8] == 0 && q[9] == 0 && q[10] == 0 && q[11] == 0);
  assert(q[end + 11] == 4 && q[n - 1] == 0);
  auto v6 = question(28); len = v6.size(); v6.resize(512);
  assert(parseQuery(v6.data(), len, name, &type, &end));
  n = buildBlocked(v6.data(), end, type);
  assert(n == end + 28 && v6[end + 3] == 28 && v6[end + 11] == 16);
  for (int i = end + 12; i < n; ++i) assert(v6[i] == 0);
  auto other = question(65); len = other.size(); other.resize(512);
  assert(parseQuery(other.data(), len, name, &type, &end));
  assert(buildBlocked(other.data(), end, type) == end && other[7] == 0 && other[11] == 0);
  auto bad = question(); bad[5] = 2;
  assert(!parseQuery(bad.data(), bad.size(), name, &type, &end));
  bad = question(); bad[12] = 64;
  assert(!parseQuery(bad.data(), bad.size(), name, &type, &end));
  bad = question(); bad[12] = 0xc0;
  assert(!parseQuery(bad.data(), bad.size(), name, &type, &end));
  bad = question(); bad[2] |= 0x80;
  assert(!parseQuery(bad.data(), bad.size(), name, &type, &end));
  bad = question(); bad[32] = 3;
  assert(!parseQuery(bad.data(), bad.size(), name, &type, &end));
  auto good = question();
  for (size_t truncated = 0; truncated < 33; ++truncated)
    assert(!parseQuery(good.data(), truncated, name, &type, &end));
  assert(buildError(good.data(), 2) == 12 && good[3] == 0x82 && good[5] == 0);
  std::mt19937 rng(77);
  uint8_t random[1600];
  for (int t = 0; t < 50000; ++t) {
    size_t length = rng() % sizeof(random);
    for (size_t i = 0; i < length; ++i) random[i] = rng();
    parseQuery(random, length, name, &type, &end);
  }
}
void lookupTests() {
  assert(fnv40("hello", 5) == (0xa430d84680aabd0bULL & HASH_MASK));
  const uint32_t sizes[] = {1,2,4095,4096,537000,1050000,2700000};
  for (uint32_t count : sizes) {
    std::vector<uint8_t> blob((size_t)count * HASH_BYTES);
    for (uint32_t i = 0; i < count; ++i) packHash((uint64_t)i * 2 + 17, blob.data() + i * HASH_BYTES);
    uint8_t index[INDEX_ENTRIES][HASH_BYTES], scratch[MAX_RANGE * HASH_BYTES];
    for (int i = 0; i < INDEX_ENTRIES; ++i) {
      uint32_t pos = (uint64_t)i * (count - 1) / (INDEX_ENTRIES - 1);
      memcpy(index[i], blob.data() + pos * HASH_BYTES, HASH_BYTES);
    }
    auto read = [&](uint32_t offset, uint8_t* dest, size_t bytes) {
      assert(offset + bytes <= blob.size() && bytes <= sizeof(scratch));
      memcpy(dest, blob.data() + offset, bytes); return true;
    };
    auto contains = [&](uint64_t h) { return indexedContains(h, count, index, scratch, read); };
    assert(!contains(16) && contains(17) && contains((uint64_t)(count - 1) * 2 + 17));
    assert(!contains((uint64_t)(count - 1) * 2 + 18));
    for (uint32_t i = 0; i < count; i += std::max(1u, count / 20000)) {
      assert(contains((uint64_t)i * 2 + 17));
      assert(!contains((uint64_t)i * 2 + 18));
    }
    // Test values beyond the old 256-entry truncation at each bucket boundary.
    for (int i = 1; i < INDEX_ENTRIES; ++i) {
      uint32_t pos = (uint64_t)i * (count - 1) / (INDEX_ENTRIES - 1);
      if (pos) assert(contains((uint64_t)(pos - 1) * 2 + 17));
    }
  }
  assert(validDomain("ads.example.com") && validDomain("_service.example.com"));
  assert(!validDomain("<script>.com") && !validDomain("bad..com") && !validDomain("-bad.com"));
  assert(domainMatches("a.b.example.com", "example.com"));
  assert(!domainMatches("notexample.com", "example.com"));
  assert(domainMatches("example.com", "example.com"));
}
int main() {
  wireTests(); lookupTests();
  std::cout << "PASS: DNS wire validation, IPv4/IPv6 sinkholes, EDNS trimming, 50000 malformed-input trials, domain matching and indexed lookups through 2700000 entries.\n";
}
