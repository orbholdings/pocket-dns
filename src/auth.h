#pragma once
#include <Preferences.h>
#include <WebServer.h>
#include <esp_system.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
namespace pdns {
inline String randomHex(unsigned n) {static const char* hex="0123456789abcdef";String out;out.reserve(n*2);for(unsigned i=0;i<n;i++){uint8_t b=esp_random();out+=hex[b>>4];out+=hex[b&15];}return out;}
inline String hexString(const uint8_t* p,size_t n){static const char* h="0123456789abcdef";String s;s.reserve(n*2);while(n--){s+=h[*p>>4];s+=h[*p++&15];}return s;}
inline bool unhex(const String& s,uint8_t* out,size_t n) {if(s.length()!=n*2)return false;for(unsigned i=0;i<n;i++){unsigned v=0;for(unsigned j=0;j<2;j++){char c=s[2*i+j];if(c>='0'&&c<='9')v=(v<<4)|(c-'0');else if(c>='a'&&c<='f')v=(v<<4)|(c-'a'+10);else return false;}out[i]=v;}return true;}
inline bool equalSecret(const String& a,const String& b){size_t n=a.length();uint32_t d=n^b.length();for(size_t i=0;i<n;i++)d|=uint8_t(a[i])^uint8_t(i<b.length()?b[i]:0);return d==0;}
inline String sha256Text(const String& s){uint8_t hash[32];mbedtls_sha256_ret((const uint8_t*)s.c_str(),s.length(),hash,0);return hexString(hash,32);}
inline String passwordHash(const String& password,const String& salt) {
  // PBKDF2-HMAC-SHA256, 12,000 iterations. The ASCII random salt is 128 bits.
  const auto* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);uint8_t u[32],key[32];
  String first=salt;first+='\0';first+='\0';first+='\0';first+='\1';
  mbedtls_md_hmac(md,(const uint8_t*)password.c_str(),password.length(),(const uint8_t*)first.c_str(),first.length(),u);memcpy(key,u,32);
  for(unsigned i=1;i<12000;i++){mbedtls_md_hmac(md,(const uint8_t*)password.c_str(),password.length(),u,32,u);for(unsigned j=0;j<32;j++)key[j]^=u[j];if(i%256==0)delay(0);}
  return hexString(key,32);
}
class Auth {
  Preferences prefs_;String salt_,hash_,session_,haHash_;uint32_t sessionAt_=0,window_=0;unsigned failures_=0;
public:
  String setupPassword;
  bool begin(){if(!prefs_.begin("pdns-sec",false))return false;String stored=prefs_.getString("admin","");if(stored.length()==96){salt_=stored.substring(0,32);hash_=stored.substring(32);}haHash_=prefs_.getString("ha","");setupPassword=prefs_.getString("ap","");if(setupPassword.length()!=16){setupPassword=randomHex(8);if(!prefs_.putString("ap",setupPassword))return false;}return true;}
  bool configured()const{return salt_.length()==32&&hash_.length()==64;}
  bool setPassword(const String& pass){if(pass.length()<8||pass.length()>64)return false;String salt=randomHex(16),hash=passwordHash(pass,salt);if(!prefs_.putString("admin",salt+hash))return false;salt_=salt;hash_=hash;session_="";return true;}
  bool verify(const String& pass)const{return configured()&&pass.length()<=64&&equalSecret(passwordHash(pass,salt_),hash_);}
  bool login(const String& pass,WebServer& web){if(uint32_t(millis()-window_)>60000){failures_=0;window_=millis();}if(failures_>=5)return false;if(!verify(pass)){failures_++;return false;}failures_=0;session_=randomHex(24);sessionAt_=millis();web.sendHeader("Set-Cookie","pdns_session="+session_+"; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600");return true;}
  bool admin(WebServer& web){if(!session_.length()||uint32_t(millis()-sessionAt_)>=3600000)return false;String cookie=web.header("Cookie");String needle="pdns_session=";int start=cookie.indexOf(needle);if(start<0||(start>0&&cookie[start-1]!=' '&&cookie[start-1]!=';'))return false;start+=needle.length();int end=cookie.indexOf(';',start);String value=cookie.substring(start,end<0?cookie.length():end);return equalSecret(value,session_);}
  bool bearer(WebServer& web)const {String h=web.header("Authorization");return haHash_.length()==64&&h.startsWith("Bearer ")&&h.length()==71&&equalSecret(sha256Text(h.substring(7)),haHash_);}
  void logout(WebServer& web){session_="";web.sendHeader("Set-Cookie","pdns_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");}
  String createHa(){String token=randomHex(32),hash=sha256Text(token);if(!prefs_.putString("ha",hash))return "";haHash_=hash;return token;}
  bool revokeHa(){bool ok=prefs_.remove("ha")||!haHash_.length();if(ok)haHash_="";return ok;}
  bool hasHa()const{return haHash_.length()==64;}
  bool reset(){session_="";hash_=salt_=haHash_="";return prefs_.clear();}
};
}
