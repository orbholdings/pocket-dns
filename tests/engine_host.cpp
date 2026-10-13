#include "dns_engine.h"
#include <chrono>
#include <cassert>
#include <thread>
#include <iostream>
#include <signal.h>
#include <arpa/inet.h>
using namespace pdns;
static bool alive=true;static auto start=std::chrono::steady_clock::now();static uint32_t seed=3;
int main(int argc,char** argv){signal(SIGTERM,[](int){alive=false;});signal(SIGPIPE,SIG_IGN);DnsEngine engine;EngineSettings s;s.listenPort=atoi(argv[1]);s.upstreamPort=atoi(argv[2]);s.primary=inet_addr("127.0.0.1");s.backup=inet_addr("127.0.0.2");s.timeoutMs=180;Hooks h;h.clock=[](void*) -> uint32_t{return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();};h.random=[](void*) -> uint32_t{return ++seed;};h.filter=[](void*,uint32_t,const char* d){Decision x;if(!strcmp(d,"blocked.test")){x.blocked=true;x.reason="test rule";}return x;};assert(engine.begin(s,h));std::cout<<"READY"<<std::endl;while(alive){engine.poll();std::this_thread::sleep_for(std::chrono::milliseconds(1));}const auto& m=engine.metrics();std::cout<<"queries="<<m.queries<<" blocked="<<m.blocked<<" backup="<<m.backupUsed<<" tcp="<<m.tcpUsed<<" cache="<<engine.cache().hits<<std::endl;}
