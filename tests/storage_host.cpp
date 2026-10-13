#include "storage.h"
#include <cassert>
#include <iostream>
using namespace pdns;
int main(){SettingsStore store;Settings a,b,out;a.appendRule("one.test",true);assert(store.save(a,b));const auto baseline=files;
 for(int cut=0;cut<300;cut+=7){files=baseline;SettingsStore update;assert(update.load(a,b));Settings next=a;strcpy(next.primary,"1.1.1.1");next.appendRule("two.test",false);writeBudget=cut;bool success=update.save(next,b);writeBudget=-1;SettingsStore reboot;assert(reboot.load(out,b));if(!success){assert(!strcmp(out.primary,"9.9.9.9"));assert(out.allowCount==1);}}
 files=baseline;SettingsStore update;assert(update.load(a,b));strcpy(a.primary,"1.1.1.1");assert(update.save(a,a));SettingsStore reboot;assert(reboot.load(out,b));assert(!strcmp(out.primary,"1.1.1.1"));files["/config-b.dat"].back()^=1;SettingsStore recover;assert(recover.load(out,b));assert(!strcmp(out.primary,"9.9.9.9"));std::cout<<"A/B settings survive interrupted writes and corrupted latest copy.\n";}
