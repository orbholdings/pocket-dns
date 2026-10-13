#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <map>
#include <algorithm>
#include <cstring>
using String=std::string;
static std::map<std::string,std::vector<uint8_t>> files;
static int writeBudget=-1;
struct File{std::string key;size_t position=0;bool exists=false;
 explicit operator bool()const{return exists;}
 size_t size(){return files[key].size();}
 size_t read(uint8_t* p,size_t n){n=std::min(n,files[key].size()-position);if(n)memcpy(p,files[key].data()+position,n);position+=n;return n;}
 int read(){return files[key][position++];}
 bool available(){return position<files[key].size();}
 size_t write(const uint8_t* p,size_t n){if(writeBudget>=0){n=std::min<size_t>(n,writeBudget);writeBudget-=n;}files[key].insert(files[key].end(),p,p+n);return n;}
 void flush(){}void close(){}
};
struct MockFS{File open(const char* key,const char* mode){File f;f.key=key;f.exists=files.count(key)||*mode=='w';if(*mode=='w')files[key].clear();return f;}};
static MockFS LittleFS;
