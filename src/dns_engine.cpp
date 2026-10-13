#include "dns_engine.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <string.h>

namespace pdns {
static bool again() { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS; }
static int nonblockingSocket(int type) {
  int fd = socket(AF_INET, type, 0);
  if (fd < 0) return -1;
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }
  return fd;
}
static sockaddr_in address(uint32_t ip, uint16_t port) {
  sockaddr_in result{}; result.sin_family = AF_INET;
  result.sin_addr.s_addr = ip; result.sin_port = htons(port); return result;
}
static bool ready(int fd, bool write) {
  if (fd < 0 || fd >= FD_SETSIZE) return false;
  fd_set set; FD_ZERO(&set); FD_SET(fd, &set); timeval timeout{};
  int result = select(fd + 1, write ? nullptr : &set, write ? &set : nullptr, nullptr, &timeout);
  return result > 0 && FD_ISSET(fd, &set);
}
uint32_t DnsEngine::now() const { return hooks_.clock ? hooks_.clock(hooks_.context) : 0; }
uint16_t DnsEngine::nextId() {
  for (unsigned tries = 0; tries < 128; ++tries) {
    uint16_t id = hooks_.random ? hooks_.random(hooks_.context) : uint16_t(now() + tries);
    bool used = false;
    for (const auto& r : requests_) if (r.state != State::Free && r.id == id) used = true;
    if (!used) return id;
  }
  for (uint32_t id = 0; id <= 65535; ++id) {
    bool used = false; for (const auto& r : requests_) if (r.state != State::Free && r.id == id) used = true;
    if (!used) return id;
  }
  return 0;
}
DnsEngine::~DnsEngine() {
  for (auto& r : requests_) closeRequest(r);
  for (auto& p : peers_) closePeer(p);
  for (int fd : {udp_, upstream_, listener_}) if (fd >= 0) close(fd);
}
bool DnsEngine::begin(const EngineSettings& settings, const Hooks& hooks) {
  settings_ = settings; hooks_ = hooks;
  udp_ = nonblockingSocket(SOCK_DGRAM); upstream_ = nonblockingSocket(SOCK_DGRAM);
  listener_ = nonblockingSocket(SOCK_STREAM);
  if (udp_ < 0 || upstream_ < 0 || listener_ < 0) return false;
  int one = 1; setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in local = address(settings.bindAddress, settings.listenPort);
  sockaddr_in ephemeral = address(settings.bindAddress, 0);
  if (bind(udp_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) ||
      bind(upstream_, reinterpret_cast<sockaddr*>(&ephemeral), sizeof(ephemeral)) ||
      bind(listener_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) || listen(listener_, TCP_CLIENTS)) return false;
  return true;
}
unsigned DnsEngine::pending() const { unsigned n = 0; for (const auto& r : requests_) if (r.state != State::Free) ++n; return n; }
unsigned DnsEngine::tcpClients() const { unsigned n = 0; for (const auto& p : peers_) if (p.fd >= 0) ++n; return n; }
void DnsEngine::closeRequest(Request& r) { if (r.fd >= 0) close(r.fd); r.fd = -1; r.state = State::Free; }
void DnsEngine::closePeer(Peer& p) {
  if (p.fd >= 0) close(p.fd);
  unsigned index = &p - peers_;
  for (auto& r : requests_) if (r.state != State::Free && r.peer == int(index)) closeRequest(r);
  p.fd = -1; p.busy = p.writing = false; p.moved = p.expected = p.sending = 0; p.prefixMoved = 0;
}
void DnsEngine::report(uint32_t ip, const Question& q, uint32_t started, Result result,
                       const char* reason, uint8_t rcode, bool tcp, bool backup, bool internal) {
  uint32_t elapsed = now() - started;
  if (!internal && result != Result::Portal) {
    if (result == Result::Blocked) ++metrics_.blocked;
    else if (result == Result::Error) ++metrics_.failed;
    else ++metrics_.allowed;
    ++metrics_.answered; metrics_.latencyTotal += elapsed;
    if (backup) ++metrics_.backupUsed;
  }
  if (hooks_.event) {
    Event e;e.ip=ip;e.at=now();e.domain=q.domain;e.reason=reason;e.result=result;e.type=q.type;
    e.elapsed=uint16_t(std::min<uint32_t>(65535,elapsed));e.rcode=rcode;e.tcp=tcp;e.backup=backup;e.internal=internal;
    hooks_.event(hooks_.context, e);
  }
}
void DnsEngine::deliver(uint32_t ip, uint16_t port, int peer, const uint8_t* data, size_t n,
                        const uint8_t* request, size_t queryBytes, uint16_t limit) {
  if (peer == -2) return;
  if (peer >= 0) {
    Peer& p = peers_[peer]; if (p.fd < 0 || n > PACKET_MAX) return;
    memcpy(p.packet, data, n); put16(p.prefix, n); p.sending = n;
    p.moved = p.prefixMoved = 0; p.writing = true; p.busy = false; p.touched = now();
  } else {
    sockaddr_in to = address(ip, port);
    if (n > limit) { size_t len = truncated(scratch_, request, queryBytes); sendto(udp_, scratch_, len, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)); }
    else sendto(udp_, data, n, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
  }
}
void DnsEngine::finish(Request& r, uint8_t* response, size_t bytes, Result result, const char* reason) {
  memcpy(response, r.query, 2);
  Question answer;
  if (question(response, bytes, answer, true) && answer.end == r.question.end && !answer.compressed && !r.question.compressed)
    memcpy(response + 12, r.query + 12, r.question.end - 12);
  if (result == Result::Allowed || result == Result::Bypass) cache_.put(r.question, response, bytes, now());
  deliver(r.ip, r.port, r.peer, response, bytes, r.query, r.bytes, r.question.udpLimit);
  report(r.ip, r.question, r.started, result, reason, response[3] & 15, r.peer >= 0, r.backup, r.internal);
  closeRequest(r);
}
void DnsEngine::fallback(Request& r, const char* why) {
  if (r.fd >= 0) { close(r.fd); r.fd = -1; }
  if (!r.backup && settings_.useBackup && settings_.backup && settings_.backup != settings_.primary) {
    r.backup = true; r.target = settings_.backup; r.stageAt = now();
    if (sendUpstream(r)) return;
  }
  memcpy(r.response, r.query, r.bytes); size_t n = error(r.response, r.bytes, 2);
  finish(r, r.response, n, Result::Error, why);
}
bool DnsEngine::sendUpstream(Request& r) {
  r.id = nextId();
  memcpy(scratch_, r.query, r.bytes); put16(scratch_, r.id);
  sockaddr_in target = address(r.target, settings_.upstreamPort);
  int written = sendto(upstream_, scratch_, r.bytes, 0, reinterpret_cast<sockaddr*>(&target), sizeof(target));
  if (written != r.bytes) return false;
  r.state = State::Udp; r.stageAt = now(); return true;
}
void DnsEngine::submit(const uint8_t* packet, size_t size, uint32_t ip, uint16_t port, int peer, bool internal) {
  if (size < 12 || packet[2] & 0x80) return;
  Question q;
  if (!question(packet, size, q) || size>QUERY_MAX) {
    memcpy(scratch_, packet, std::min(size, PACKET_MAX)); size_t n = error(scratch_, std::min(size, PACKET_MAX), 1);
    deliver(ip, port, peer, scratch_, n, packet, std::min(size, PACKET_MAX), 512);
    ++metrics_.rejected; return;
  }
  if (!internal) ++metrics_.queries;
  uint32_t started = now();
  Decision decision = hooks_.filter ? hooks_.filter(hooks_.context, ip, q.domain) : Decision{};
  if (decision.blocked || decision.portalAddress) {
    memcpy(scratch_, packet, size);
    size_t n = sinkhole(scratch_, size, q, decision.portalAddress);
    deliver(ip, port, peer, scratch_, n, packet, size, q.udpLimit);
    report(ip, q, started, decision.portalAddress ? Result::Portal : Result::Blocked, decision.reason, 0, peer >= 0, false, internal);
    return;
  }
  size_t cachedBytes = 0;
  if (cache_.get(q, packet, size, started, scratch_, cachedBytes)) {
    deliver(ip, port, peer, scratch_, cachedBytes, packet, size, q.udpLimit);
    report(ip, q, started, Result::Cached, "answer cache", scratch_[3] & 15, peer >= 0, false, internal); return;
  }
  Request* slot = nullptr;
  for (auto& r : requests_) if (r.state == State::Free) { slot = &r; break; }
  if (!slot) {
    memcpy(scratch_, packet, size); size_t n = error(scratch_, size, 2);
    deliver(ip, port, peer, scratch_, n, packet, size, q.udpLimit);
    report(ip, q, started, Result::Error, "request queue full", 2, peer >= 0, false, internal); ++metrics_.rejected; return;
  }
  Request& r = *slot;
  r.question = q; memcpy(r.query, packet, size); r.bytes = size;
  r.ip = ip; r.port = port; r.peer = peer; r.internal = internal;
  r.started = r.stageAt = started; r.target = settings_.primary; r.backup = false; r.bypass = decision.bypass;
  r.fd = -1; r.state = State::Udp;
  if (!sendUpstream(r)) fallback(r, "upstream send failed");
}
void DnsEngine::receiveUdp() {
  for (unsigned budget = 0; budget < 8; ++budget) {
    sockaddr_in from{}; socklen_t length = sizeof(from);
    int n = recvfrom(udp_, scratch_, sizeof(scratch_), 0, reinterpret_cast<sockaddr*>(&from), &length);
    if (n <= 0) break;
    if(n>int(PACKET_MAX)){++metrics_.rejected;continue;}
    // submit may reuse scratch_; preserve the packet in a free request buffer first.
    uint8_t* input = nullptr;
    for (auto& r : requests_) if (r.state == State::Free) { input = r.response; break; }
    if (input) { memcpy(input, scratch_, n); submit(input, n, from.sin_addr.s_addr, ntohs(from.sin_port), -1, false); }
    else {
      Question q; if (question(scratch_, n, q)) {
        ++metrics_.queries; size_t bytes = error(scratch_, n, 2);
        sendto(udp_, scratch_, bytes, 0, reinterpret_cast<sockaddr*>(&from), length);
        report(from.sin_addr.s_addr, q, now(), Result::Error, "request queue full", 2, false, false, false); ++metrics_.rejected;
      }
    }
  }
}
void DnsEngine::receiveUpstream() {
  for (unsigned budget = 0; budget < 8; ++budget) {
    sockaddr_in from{}; socklen_t length = sizeof(from);
    int n = recvfrom(upstream_, scratch_, sizeof(scratch_), 0, reinterpret_cast<sockaddr*>(&from), &length);
    if (n <= 0) break;
    if(n>int(PACKET_MAX)){for(auto& r:requests_)if(r.state==State::Udp&&from.sin_addr.s_addr==r.target&&ntohs(from.sin_port)==settings_.upstreamPort&&u16(scratch_)==r.id){r.state=State::TcpWait;r.stageAt=now();break;}continue;}
    Question q;
    if (!validResponse(scratch_,n) || !question(scratch_, n, q, true) || ntohs(from.sin_port) != settings_.upstreamPort) continue;
    for (auto& r : requests_) {
      if (r.state != State::Udp || from.sin_addr.s_addr != r.target || u16(scratch_) != r.id || !sameQuestion(r.question, q)) continue;
      if (scratch_[2] & 2) { r.state = State::TcpWait; r.stageAt = now(); break; }
      uint8_t code = scratch_[3] & 15;
      if (code == 2 || code == 5) { fallback(r, "upstream refused or failed"); break; }
      memcpy(r.response, scratch_, n);
      finish(r, r.response, n, r.bypass ? Result::Bypass : Result::Allowed, r.backup ? "backup resolver" : "primary resolver"); break;
    }
  }
}
void DnsEngine::acceptPeers() {
  sockaddr_in from{}; socklen_t length = sizeof(from);
  int fd = accept(listener_, reinterpret_cast<sockaddr*>(&from), &length);
  if (fd < 0) return;
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return; }
  for (auto& p : peers_) if (p.fd < 0) {
    p.fd = fd; p.ip = from.sin_addr.s_addr; p.touched = now();
    p.busy = p.writing = false; p.moved = p.expected = p.sending = 0; p.prefixMoved = 0; return;
  }
  close(fd); ++metrics_.rejected;
}
void DnsEngine::servicePeers() {
  for (unsigned index = 0; index < TCP_CLIENTS; ++index) {
    Peer& p = peers_[index]; if (p.fd < 0) continue;
    if (uint32_t(now() - p.touched) > 15000) { closePeer(p); continue; }
    if (p.writing) {
      if (p.prefixMoved < 2) {
        int n = send(p.fd, p.prefix + p.prefixMoved, 2 - p.prefixMoved, 0);
        if (n < 0 && !again()) { closePeer(p); continue; }
        if (n > 0) p.prefixMoved += n;
      }
      if (p.prefixMoved == 2 && p.moved < p.sending) {
        int n = send(p.fd, p.packet + p.moved, p.sending - p.moved, 0);
        if (n < 0 && !again()) { closePeer(p); continue; }
        if (n > 0) { p.moved += n; p.touched = now(); }
      }
      if (p.moved == p.sending && p.prefixMoved == 2) { p.writing = false; p.moved = p.expected = p.sending = 0; p.prefixMoved = 0; }
      continue;
    }
    if (p.busy) continue;
    if (p.prefixMoved < 2) {
      int n = recv(p.fd, p.prefix + p.prefixMoved, 2 - p.prefixMoved, 0);
      if (!n || (n < 0 && !again())) { closePeer(p); continue; }
      if (n > 0) { p.prefixMoved += n; p.touched = now(); }
      if (p.prefixMoved < 2) continue;
      p.expected = u16(p.prefix);
      if (p.expected < 12 || p.expected > PACKET_MAX) { closePeer(p); continue; }
    }
    int n = recv(p.fd, p.packet + p.moved, p.expected - p.moved, 0);
    if (!n || (n < 0 && !again())) { closePeer(p); continue; }
    if (n > 0) { p.moved += n; p.touched = now(); }
    if (p.moved == p.expected) { p.busy = true; submit(p.packet, p.expected, p.ip, 0, index, false); }
  }
}
void DnsEngine::serviceRequests() {
  unsigned open = 0; for (const auto& r : requests_) if (r.fd >= 0) ++open;
  for (auto& r : requests_) {
    if (r.state == State::Free) continue;
    if (uint32_t(now() - r.stageAt) >= settings_.timeoutMs || uint32_t(now() - r.started) >= 3500) { fallback(r, "resolver timeout"); continue; }
    if (r.state == State::Udp) continue;
    if (r.state == State::TcpWait) {
      if (open >= UPSTREAM_TCP_LIMIT) continue;
      r.fd = nonblockingSocket(SOCK_STREAM);
      if (r.fd < 0) { fallback(r, "TCP connection unavailable"); continue; }
      ++open; sockaddr_in target = address(r.target, settings_.upstreamPort);
      int result = connect(r.fd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
      if (result && !again()) { fallback(r, "TCP connection failed"); continue; }
      r.state = result ? State::TcpConnect : State::TcpSend;
      r.frameMoved = 0; r.moved = 0; put16(r.frame, r.bytes);
      ++metrics_.tcpUsed;
    }
    if (r.state == State::TcpConnect) {
      if (!ready(r.fd, true)) continue;
      int errorCode = 0; socklen_t size = sizeof(errorCode);
      if (getsockopt(r.fd, SOL_SOCKET, SO_ERROR, &errorCode, &size) || errorCode) { fallback(r, "TCP connection failed"); continue; }
      r.state = State::TcpSend;
    }
    if (r.state == State::TcpSend) {
      if (r.frameMoved < 2) {
        int n = send(r.fd, r.frame + r.frameMoved, 2 - r.frameMoved, 0);
        if (n < 0 && !again()) { fallback(r, "TCP send failed"); continue; }
        if (n > 0) r.frameMoved += n;
      }
      if (r.frameMoved == 2 && r.moved < r.bytes) {
        // Keep the original client query intact for safe failover and error responses.
        memcpy(scratch_, r.query, r.bytes); put16(scratch_, r.id);
        int n = send(r.fd, scratch_ + r.moved, r.bytes - r.moved, 0);
        if (n < 0 && !again()) { fallback(r, "TCP send failed"); continue; }
        if (n > 0) r.moved += n;
      }
      if (r.frameMoved == 2 && r.moved == r.bytes) { r.state = State::TcpLength; r.frameMoved = 0; r.moved = 0; }
    }
    if (r.state == State::TcpLength) {
      int n = recv(r.fd, r.frame + r.frameMoved, 2 - r.frameMoved, 0);
      if (!n || (n < 0 && !again())) { fallback(r, "TCP reply interrupted"); continue; }
      if (n > 0) r.frameMoved += n;
      if (r.frameMoved < 2) continue;
      r.expected = u16(r.frame);
      if (r.expected < 12 || r.expected > PACKET_MAX) { fallback(r, "TCP reply exceeds limit"); continue; }
      r.state = State::TcpRead;
    }
    if (r.state == State::TcpRead) {
      int n = recv(r.fd, r.response + r.moved, r.expected - r.moved, 0);
      if (!n || (n < 0 && !again())) { fallback(r, "TCP reply interrupted"); continue; }
      if (n > 0) r.moved += n;
      if (r.moved != r.expected) continue;
      Question q;
      if (!validResponse(r.response,r.expected) || !question(r.response, r.expected, q, true) || !sameQuestion(r.question, q) || u16(r.response) != r.id || (r.response[2] & 2)) {
        fallback(r, "invalid TCP reply"); continue;
      }
      uint8_t code = r.response[3] & 15;
      if (code == 2 || code == 5) { fallback(r, "TCP resolver refused or failed"); continue; }
      finish(r, r.response, r.expected, r.bypass ? Result::Bypass : Result::Allowed, r.backup ? "backup resolver over TCP" : "primary resolver over TCP");
    }
  }
}
void DnsEngine::poll() { if (!running()) return; acceptPeers(); receiveUpstream(); serviceRequests(); servicePeers(); receiveUdp(); }
void DnsEngine::invalidate() {
  cache_.clear();
  for (auto& r : requests_) if (r.state != State::Free) {
    memcpy(r.response, r.query, r.bytes); size_t n = error(r.response, r.bytes, 2);
    finish(r, r.response, n, Result::Error, "settings changed");
  }
}
void DnsEngine::configure(const EngineSettings& settings) { invalidate(); settings_.primary = settings.primary; settings_.backup = settings.backup; settings_.useBackup = settings.useBackup; settings_.timeoutMs = settings.timeoutMs; }
bool DnsEngine::internalQuery(const char* domain, uint16_t type) {
  uint8_t input[280]; size_t len = makeQuery(domain, type, nextId(), input, sizeof(input));
  if (!len || pending() == REQUEST_SLOTS) return false;
  submit(input, len, 0, 0, -2, true); return true;
}
}
