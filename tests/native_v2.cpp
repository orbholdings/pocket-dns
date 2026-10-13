#include "dns_packet.h"
#include "settings.h"
#include <cassert>
#include <iostream>
#include <random>
using namespace pdns;
int main(){
 uint8_t q[4096]{},a[4096]{},out[4096]{};size_t qn=makeQuery("Example.COM",1,123,q,sizeof(q));Question questionA;assert(question(q,qn,questionA));assert(!strcmp(questionA.domain,"example.com"));
 memcpy(a,q,qn);size_t an=sinkhole(a,qn,questionA);assert(validResponse(a,an));a[an-4]=1;a[an-3]=2;a[an-2]=3;a[an-1]=4;AnswerCache cache;assert(cache.put(questionA,a,an,0));size_t n=0;put16(q,456);assert(cache.get(questionA,q,qn,10000,out,n));assert(u16(out)==456&&u32(out+qn+6)==50);assert(!cache.get(questionA,q,qn,60000,out,n));
 // Negative caching uses min(SOA TTL, SOA MINIMUM).
 memcpy(a,q,qn);a[2]=0x81;a[3]=0x83;put16(a+8,1);size_t p=qn;put16(a+p,0xc00c);put16(a+p+2,6);put16(a+p+4,1);put32(a+p+6,120);put16(a+p+10,24);p+=12;put16(a+p,0xc00c);put16(a+p+2,0xc00c);memset(a+p+4,0,20);put32(a+p+20,30);p+=24;assert(validResponse(a,p));TtlMap map;assert(cacheTtls(a,p,map)&&map.lifetime==30);assert(cache.put(questionA,a,p,0));assert(cache.get(questionA,q,qn,29000,out,n));assert(u32(out+qn+6)==1);assert(!cache.get(questionA,q,qn,30000,out,n));
 // ECS / cookie / option-bearing queries cannot use a shared cache.
 qn=makeQuery("example.com",1,1,q,sizeof(q));put16(q+10,1);p=qn;q[p++]=0;put16(q+p,41);put16(q+p+2,1232);put32(q+p+4,0x8000);put16(q+p+8,4);p+=10;put16(q+p,10);put16(q+p+2,0);p+=4;assert(question(q,p,questionA)&&!questionA.cacheable&&questionA.udpLimit==1232);
 // Compression cycles, impossible counts and short resource records are rejected.
 memset(q,0,20);q[5]=1;q[12]=0xc0;q[13]=12;assert(!question(q,20,questionA));a[qn+11]=255;assert(!validResponse(a,qn+12));
 std::mt19937 rng(1234);for(unsigned i=0;i<50000;i++){size_t bytes=rng()%4096;for(size_t j=0;j<bytes;j++)q[j]=rng();Question t;question(q,bytes,t);validResponse(q,bytes);cacheTtls(q,bytes,map);}
 Settings settings,scratch;assert(settings.appendRule("example.com",true));assert(settings.matches("www.example.com",true));assert(!settings.matches("otherexample.com",true));DynamicJsonDocument doc(24576);settingsToJson(settings,doc.to<JsonObject>());const char* error;assert(settingsFromJson(doc.as<JsonVariantConst>(),scratch,error));assert(scratch.allowCount==1);doc["schema"]=1;assert(!settingsFromJson(doc.as<JsonVariantConst>(),scratch,error));doc["schema"]=2;doc["primary"]="999.1.1.1";assert(!settingsFromJson(doc.as<JsonVariantConst>(),scratch,error));doc["primary"]="9.9.9.9";doc["devices"].as<JsonArray>().add(doc.createNestedObject("bad"));assert(!settingsFromJson(doc.as<JsonVariantConst>(),scratch,error));
 assert(crc32((const uint8_t*)"123456789",9)==0xcbf43926);std::cout<<"Protocol/cache/config tests and 50,000 malformed packet cases passed.\n";
}
