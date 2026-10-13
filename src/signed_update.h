#pragma once
#include <Update.h>
#include <esp_ota_ops.h>
#include <ArduinoJson.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include "auth.h"
#include "build_info.h"
#include "update_public_key.h"
namespace pdns {
class SignedUpdate {
  uint8_t header_[2060]{};uint32_t headerUsed_=0,headerNeed_=12,written_=0,expected_=0,startedAt_=0;
  uint8_t expectedHash_[32]{};bool active_=false,streaming_=false,complete_=false;
  mbedtls_sha256_context sha_{};
  bool manifest(){
    DynamicJsonDocument d(4096);if(deserializeJson(d,header_+12,headerNeed_-12)){fail("Invalid update manifest");return false;}
    const char* chip=d["chip"],*layout=d["layout"],*part=d["partition_sha256"],*hash=d["sha256"],*version=d["version"],*sig=d["signature"];
    if(!chip||!layout||!part||!hash||!version||!sig||strlen(version)>24||strlen(sig)>160||!d["version_code"].is<uint32_t>()||!d["bytes"].is<uint32_t>()){fail("Incomplete update manifest");return false;}
    uint32_t code=d["version_code"],bytes=d["bytes"];
    if(strcmp(chip,PDNS_CHIP)||strcmp(layout,PDNS_LAYOUT)||strcmp(part,PDNS_PARTITION_SHA256)){fail("This update is for a different board or flash layout");return false;}
    if(code<PDNS_VERSION_CODE){fail("Older firmware is not accepted");return false;}
    const esp_partition_t* target=esp_ota_get_next_update_partition(nullptr);
    if(!target||bytes<100000||bytes>target->size||!unhex(hash,expectedHash_,32)){fail("Invalid image size or checksum");return false;}
    String canonical=String("PocketDNS update v2\n")+chip+"\n"+layout+"\n"+part+"\n"+version+"\n"+String(code)+"\n"+String(bytes)+"\n"+hash+"\n";
    uint8_t digest[32],signature[80];size_t sigBytes=strlen(sig)/2;
    if(strlen(sig)%2||sigBytes<64||!unhex(sig,signature,sigBytes)){fail("Invalid update signature");return false;}
    mbedtls_sha256_ret((const uint8_t*)canonical.c_str(),canonical.length(),digest,0);
    mbedtls_pk_context key;mbedtls_pk_init(&key);int rc=mbedtls_pk_parse_public_key(&key,(const uint8_t*)PDNS_UPDATE_PUBLIC_KEY,strlen(PDNS_UPDATE_PUBLIC_KEY)+1);
    if(!rc)rc=mbedtls_pk_verify(&key,MBEDTLS_MD_SHA256,digest,32,signature,sigBytes);mbedtls_pk_free(&key);
    if(rc){fail("Signature is not trusted");return false;}
    if(!Update.begin(bytes,U_FLASH)){fail("Cannot open inactive firmware partition");return false;}
    expected_=bytes;mbedtls_sha256_starts_ret(&sha_,0);streaming_=true;return true;
  }
public:
  String error;
  SignedUpdate(){mbedtls_sha256_init(&sha_);}
  ~SignedUpdate(){mbedtls_sha256_free(&sha_);}
  void start(){if(active_)Update.abort();headerUsed_=written_=0;headerNeed_=12;expected_=0;active_=true;streaming_=complete_=false;error="";startedAt_=millis();}
  void fail(const char* reason){if(error.isEmpty())error=reason;if(streaming_)Update.abort();active_=streaming_=complete_=false;}
  void feed(const uint8_t* bytes,size_t n){
    if(!active_)return;
    while(n&&!streaming_){size_t amount=std::min<size_t>(n,headerNeed_-headerUsed_);memcpy(header_+headerUsed_,bytes,amount);headerUsed_+=amount;bytes+=amount;n-=amount;
      if(headerUsed_==12&&headerNeed_==12){if(memcmp(header_,"PDNS2UPD",8)){fail("Select a signed .pdu package, not a .bin file");return;}uint32_t len;memcpy(&len,header_+8,4);if(len<128||len>2048){fail("Update header exceeds limit");return;}headerNeed_=12+len;}
      if(headerUsed_==headerNeed_&&!manifest())return;
    }
    if(n){if(written_+n>expected_){fail("Update contains extra data");return;}mbedtls_sha256_update_ret(&sha_,bytes,n);if(Update.write(const_cast<uint8_t*>(bytes),n)!=n){fail("Flash write failed");return;}written_+=n;}
  }
  bool finish(){if(!active_||!streaming_||written_!=expected_){fail("Update is incomplete");return false;}uint8_t hash[32];mbedtls_sha256_finish_ret(&sha_,hash);if(memcmp(hash,expectedHash_,32)){fail("Image checksum does not match the signed manifest");return false;}if(!Update.end()){fail("Firmware image validation failed");return false;}complete_=true;active_=streaming_=false;return true;}
  void poll(){if(active_&&uint32_t(millis()-startedAt_)>120000)fail("Update timed out");}
  bool busy()const{return active_;}
  bool complete()const{return complete_;}
};
}
