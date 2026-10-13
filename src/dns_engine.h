#pragma once
#include "dns_packet.h"
#include <stdint.h>
#include <stddef.h>

namespace pdns {
constexpr unsigned REQUEST_SLOTS = 6;
constexpr unsigned QUERY_MAX = 1024;
constexpr unsigned TCP_CLIENTS = 3;
constexpr unsigned UPSTREAM_TCP_LIMIT = 2;
enum class Result : uint8_t { Allowed, Blocked, Cached, Bypass, Error, Portal };
struct Decision {
  bool blocked = false, bypass = false;
  uint32_t portalAddress = 0;
  const char* reason = "allowed";
};
struct Event {
  uint32_t ip = 0, at = 0;
  const char* domain = nullptr;
  const char* reason = nullptr;
  Result result = Result::Allowed;
  uint16_t type = 0, elapsed = 0;
  uint8_t rcode = 0;
  bool tcp = false, backup = false, internal = false;
};
struct Hooks {
  void* context = nullptr;
  uint32_t (*clock)(void*) = nullptr;
  uint32_t (*random)(void*) = nullptr;
  Decision (*filter)(void*, uint32_t, const char*) = nullptr;
  void (*event)(void*, const Event&) = nullptr;
};
struct EngineSettings {
  uint32_t primary = 0, backup = 0;
  uint16_t listenPort = 53, upstreamPort = 53;
  uint32_t bindAddress = 0;
  bool useBackup = true;
  uint16_t timeoutMs = 700;
};
struct Metrics {
  uint32_t queries = 0, blocked = 0, allowed = 0, failed = 0;
  uint32_t backupUsed = 0, tcpUsed = 0, rejected = 0;
  uint64_t latencyTotal = 0;
  uint32_t answered = 0;
};
class DnsEngine {
  enum class State : uint8_t { Free, Udp, TcpWait, TcpConnect, TcpSend, TcpLength, TcpRead };
  struct Request {
    uint8_t query[QUERY_MAX]{};
    uint8_t response[PACKET_MAX]{};
    Question question{};
    uint32_t ip = 0, started = 0, stageAt = 0, target = 0;
    uint16_t port = 0, id = 0, bytes = 0, expected = 0, moved = 0;
    uint8_t frame[2]{};
    uint8_t frameMoved = 0;
    int fd = -1, peer = -1;
    State state = State::Free;
    bool backup = false, internal = false, bypass = false;
  } requests_[REQUEST_SLOTS];
  struct Peer {
    uint8_t packet[PACKET_MAX]{};
    uint8_t prefix[2]{};
    uint16_t moved = 0, expected = 0, sending = 0;
    uint8_t prefixMoved = 0;
    int fd = -1;
    uint32_t ip = 0, touched = 0;
    bool busy = false, writing = false;
  } peers_[TCP_CLIENTS];
  uint8_t scratch_[PACKET_MAX+1]{};
  int udp_ = -1, upstream_ = -1, listener_ = -1;
  EngineSettings settings_{};
  Hooks hooks_{};
  AnswerCache cache_{};
  Metrics metrics_{};
  uint16_t nextId();
  uint32_t now() const;
  void receiveUdp();
  void receiveUpstream();
  void servicePeers();
  void serviceRequests();
  void acceptPeers();
  void submit(const uint8_t*, size_t, uint32_t, uint16_t, int, bool);
  bool sendUpstream(Request&);
  void fallback(Request&, const char*);
  void finish(Request&, uint8_t*, size_t, Result, const char*);
  void deliver(uint32_t, uint16_t, int, const uint8_t*, size_t, const uint8_t*, size_t, uint16_t);
  void report(uint32_t, const Question&, uint32_t, Result, const char*, uint8_t, bool, bool, bool);
  void closeRequest(Request&);
  void closePeer(Peer&);
public:
  DnsEngine() = default;
  ~DnsEngine();
  bool begin(const EngineSettings&, const Hooks&);
  void poll();
  void invalidate();
  void configure(const EngineSettings&);
  bool internalQuery(const char*, uint16_t = 1);
  unsigned pending() const;
  unsigned tcpClients() const;
  const Metrics& metrics() const { return metrics_; }
  const AnswerCache& cache() const { return cache_; }
  bool running() const { return udp_ >= 0 && listener_ >= 0 && upstream_ >= 0; }
};
}
