#pragma once
#include <LittleFS.h>
#include "settings.h"
namespace pdns {
class SettingsStore {
  uint32_t revision_=0; int slot_=-1;
  bool readSlot(int slot,Settings& output,uint32_t& revision) {
    File f=LittleFS.open(slot?"/config-b.dat":"/config-a.dat","r"); if(!f)return false;
    uint32_t h[5]; if(f.read((uint8_t*)h,sizeof(h))!=sizeof(h)||h[0]!=0x32444e50||h[1]!=2||h[3]>24576||f.size()!=sizeof(h)+h[3])return false;
    String body; body.reserve(h[3]); while(f.available())body+=(char)f.read();
    if(body.length()!=h[3]||crc32((const uint8_t*)body.c_str(),body.length())!=h[4])return false;
    DynamicJsonDocument doc(24576); if(deserializeJson(doc,body))return false;
    const char* error; if(!settingsFromJson(doc.as<JsonVariantConst>(),output,error))return false;
    revision=h[2]; return true;
  }
public:
  bool load(Settings& active,Settings& scratch) {
    uint32_t a=0,b=0;bool aa=readSlot(0,active,a),bb=readSlot(1,scratch,b);
    if(bb&&(!aa||int32_t(b-a)>0)){active=scratch;revision_=b;slot_=1;return true;}
    if(aa){revision_=a;slot_=0;return true;}
    active=Settings{};return false;
  }
  bool save(const Settings& next,Settings& scratch) {
    String body;
    {DynamicJsonDocument doc(24576);settingsToJson(next,doc.to<JsonObject>());if(doc.overflowed())return false;serializeJson(doc,body);}
    if(body.length()>24576)return false;
    uint32_t h[5]={0x32444e50,2,revision_+1,uint32_t(body.length()),crc32((const uint8_t*)body.c_str(),body.length())};
    int target=slot_==0?1:0; File f=LittleFS.open(target?"/config-b.dat":"/config-a.dat","w");if(!f)return false;
    bool ok=f.write((const uint8_t*)h,sizeof(h))==sizeof(h)&&f.write((const uint8_t*)body.c_str(),body.length())==body.length();f.flush();f.close();
    body="";uint32_t check=0;if(!ok||!readSlot(target,scratch,check)||check!=h[2])return false;
    revision_=check;slot_=target;return true;
  }
  uint32_t revision() const{return revision_;}
};
}
