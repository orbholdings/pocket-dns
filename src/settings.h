#pragma once
#include <ArduinoJson.h>
#include "dns_core.h"
#include <stdint.h>
#include <string.h>

namespace pdns {
enum class Profile : uint8_t { Balanced, Strict, Bypass };
inline const char* profileName(Profile p) { return p == Profile::Strict ? "strict" : p == Profile::Bypass ? "bypass" : "balanced"; }
inline bool parseProfile(const char* s, Profile& p) {
  if (!s) return false;
  if (!strcmp(s,"balanced")) p=Profile::Balanced;
  else if (!strcmp(s,"strict")) p=Profile::Strict;
  else if (!strcmp(s,"bypass")) p=Profile::Bypass;
  else return false; return true;
}
constexpr unsigned MAX_RULES=200, RULE_BYTES=8192, MAX_DEVICE_SETTINGS=32;
struct DeviceSetting { char key[18]{}, label[33]{}; Profile profile=Profile::Balanced; bool banned=false; };
struct Settings {
  char primary[16]="9.9.9.9", backup[16]="149.112.112.112";
  bool useBackup=true, history=true, blocking=true;
  Profile profile=Profile::Balanced;
  char pool[RULE_BYTES]{};
  uint16_t allow[MAX_RULES]{}, block[MAX_RULES]{};
  uint16_t used=0, allowCount=0, blockCount=0;
  DeviceSetting devices[MAX_DEVICE_SETTINGS]{};
  uint8_t deviceCount=0;
  bool appendRule(const char* domain, bool permitted) {
    size_t n=strlen(domain); uint16_t& count=permitted?allowCount:blockCount;
    auto offsets=permitted?allow:block;
    if (!pocketdns::validDomain(domain) || count==MAX_RULES || used+n+1>RULE_BYTES) return false;
    for (unsigned i=0;i<count;i++) if (!strcmp(pool+offsets[i],domain)) return true;
    offsets[count++]=used; memcpy(pool+used,domain,n+1); used+=n+1; return true;
  }
  bool matches(const char* domain, bool permitted) const {
    auto offsets=permitted?allow:block; unsigned count=permitted?allowCount:blockCount;
    for (unsigned i=0;i<count;i++) if(pocketdns::domainMatches(domain,pool+offsets[i]))return true;
    return false;
  }
};
inline bool ipv4(const char* text) {
  if(!text)return false; unsigned parts=0,v=0,digits=0;
  for(const char* p=text;;p++) {
    if(*p>='0'&&*p<='9'){v=v*10+(*p-'0');if(++digits>3||v>255)return false;}
    else if(*p=='.'||!*p){if(!digits)return false;parts++;v=digits=0;if(!*p)break;}
    else return false;
  }
  return parts==4 && strcmp(text,"0.0.0.0") && strcmp(text,"255.255.255.255");
}
inline bool deviceKey(const char* s) {
  if(ipv4(s))return true;
  if(!s||strlen(s)!=17)return false;
  for(unsigned i=0;i<17;i++){if(i%3==2){if(s[i]!=':')return false;}else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;}
  return true;
}
inline bool settingsFromJson(JsonVariantConst v, Settings& s, const char*& error) {
  s=Settings{}; error="Invalid settings";
  if(!v.is<JsonObjectConst>() || !v["schema"].is<unsigned>() || v["schema"].as<unsigned>()!=2)return false;
  const char* primary=v["primary"], *backup=v["backup"];
  if(!ipv4(primary)||!ipv4(backup)||strlen(primary)>15||strlen(backup)>15){error="Enter valid IPv4 resolvers";return false;}
  if(!v["use_backup"].is<bool>()||!v["history"].is<bool>()||!v["blocking"].is<bool>())return false;
  strcpy(s.primary,primary);strcpy(s.backup,backup);s.useBackup=v["use_backup"];s.history=v["history"];s.blocking=v["blocking"];
  if(!parseProfile(v["profile"],s.profile)){error="Unknown default profile";return false;}
  for(bool permitted:{true,false}) {
    auto a=v[permitted?"allow":"block"];
    if(!a.is<JsonArrayConst>()||a.size()>MAX_RULES){error="Too many rules (200 per list)";return false;}
    for(JsonVariantConst item:a.as<JsonArrayConst>()) {
      const char* d=item.as<const char*>();
      if(!d||!s.appendRule(d,permitted)){error="Invalid domain or rule storage full (8 KB)";return false;}
    }
  }
  if(!v["devices"].is<JsonArrayConst>()||v["devices"].size()>MAX_DEVICE_SETTINGS){error="Too many saved devices (32)";return false;}
  for(JsonVariantConst d:v["devices"].as<JsonArrayConst>()) {
    const char* key=d["key"], *label=d["label"]; auto& dest=s.devices[s.deviceCount++];
    if(!deviceKey(key)||!label||strlen(label)>32||!parseProfile(d["profile"],dest.profile)||!d["banned"].is<bool>()){error="Invalid device settings";return false;}
    for(const char* p=label;*p;p++)if(uint8_t(*p)<32){error="Invalid device name";return false;}
    for(unsigned i=0;i+1<s.deviceCount;i++)if(!strcmp(s.devices[i].key,key)){error="Duplicate device key";return false;}
    strcpy(dest.key,key);strcpy(dest.label,label);dest.banned=d["banned"];
  }
  return true;
}
inline void settingsToJson(const Settings& s, JsonObject v) {
  v["schema"]=2;v["primary"]=s.primary;v["backup"]=s.backup;v["use_backup"]=s.useBackup;
  v["profile"]=profileName(s.profile);v["history"]=s.history;v["blocking"]=s.blocking;
  auto a=v.createNestedArray("allow"),b=v.createNestedArray("block");
  for(unsigned i=0;i<s.allowCount;i++)a.add(s.pool+s.allow[i]);
  for(unsigned i=0;i<s.blockCount;i++)b.add(s.pool+s.block[i]);
  auto devices=v.createNestedArray("devices");
  for(unsigned i=0;i<s.deviceCount;i++){auto d=devices.createNestedObject();d["key"]=s.devices[i].key;d["label"]=s.devices[i].label;d["profile"]=profileName(s.devices[i].profile);d["banned"]=s.devices[i].banned;}
}
inline uint32_t crc32(const uint8_t* p,size_t n) {uint32_t crc=~0u;while(n--){crc^=*p++;for(unsigned i=0;i<8;i++)crc=(crc>>1)^(0xedb88320u&uint32_t(-int32_t(crc&1)));}return ~crc;}
}
