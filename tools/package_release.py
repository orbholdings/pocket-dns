#!/usr/bin/env python3
"""Build and byte-verify full factory images, seed both OTA slots, sign packages."""
import argparse,hashlib,json,shutil,struct,subprocess,sys,zlib,re
from pathlib import Path
from littlefs import LittleFS
from sign_update import sign,verify
ROOT=Path(__file__).resolve().parents[1]

def partitions(data):
 result=[]
 for pos in range(0,0xc00,32):
  entry=data[pos:pos+32];magic=struct.unpack_from('<H',entry)[0]
  if magic==0xffff:break
  if magic==0xebeb:
   assert hashlib.md5(data[:pos]).digest()==entry[16:32];break
  assert magic==0x50aa
  _,kind,subtype,offset,size,label,_=struct.unpack('<HBBII16sI',entry);result.append({'name':label.split(b'\0')[0].decode(),'type':kind,'subtype':subtype,'offset':offset,'size':size})
 return result

def ota_data():
 # ESP-IDF v4.4: seq=3 selects app0; seq=2 selects app1. Both are VALID.
 # esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4) matches zlib crc32(initial=FFFFFFFF).
 result=bytearray(b'\xff'*8192)
 for offset,seq in [(0,3),(4096,2)]:result[offset:offset+32]=struct.pack('<I20sII',seq,b'\xff'*20,2,zlib.crc32(struct.pack('<I',seq),0xffffffff))
 return bytes(result)

def filesystem(size):
 fs=LittleFS(block_size=4096,block_count=size//4096,read_size=256,prog_size=256,cache_size=256,lookahead_size=16,mount=False);fs.format();fs.mount()
 for name in ['blocklist.bin','strict.bin']:
  data=(ROOT/'data'/name).read_bytes();assert len(data)%5==0
  hashes=[int.from_bytes(data[i:i+5],'little') for i in range(0,len(data),5)];assert all(a<b for a,b in zip(hashes,hashes[1:]))
  with fs.open('/'+name,'wb') as f:f.write(data)
  with fs.open('/'+name,'rb') as f:assert f.read()==data
 fs.unmount();return bytes(fs.context.buffer)

def main():
 p=argparse.ArgumentParser();p.add_argument('--key',type=Path,required=True);a=p.parse_args();release=ROOT/'release';release.mkdir(exist_ok=True);manifest={'factory_address':'0x0','boards':{}}
 pub=release/'update_public_key.pem';text=(ROOT/'src/update_public_key.h').read_text();pub.write_text(text.split('R"KEY(')[1].split(')KEY"')[0]);fs_cache={}
 for layout in ['esp32-4mb','esp32s3-4mb','esp32s3-8mb','esp32s3-16mb']:
  b=ROOT/'.pio/build'/layout;info=(b/'generated/build_info.h').read_text();version=re.search(r'#define PDNS_VERSION "([^"]+)"',info)[1];code=int(re.search(r'#define PDNS_VERSION_CODE (\d+)',info)[1]);manifest.setdefault('version',version);manifest.setdefault('version_code',code);assert manifest['version']==version and manifest['version_code']==code;chip='esp32s3' if 's3' in layout else 'esp32';mb=int(layout.split('-')[-1][:-2]);freq='80m' if chip=='esp32s3' else '40m';chip_id=9 if chip=='esp32s3' else 0
  target=release/'firmware'/layout;target.mkdir(parents=True,exist_ok=True);table=(b/'partitions.bin').read_bytes();parts=partitions(table);by_name={p['name']:p for p in parts};assert all(p['offset']+p['size']<=mb*1024*1024 for p in parts)
  for prev,next in zip(parts,parts[1:]):assert prev['offset']+prev['size']<=next['offset']
  app=(b/'firmware.bin').read_bytes();boot=(b/'bootloader.bin').read_bytes();assert len(app)<=by_name['app0']['size'] and len(app)<=by_name['app1']['size']
  for image in [app,boot]:assert image[0]==0xe9 and struct.unpack_from('<H',image,12)[0]==chip_id
  app_path=target/'application.bin';app_path.write_bytes(app);(target/'bootloader.bin').write_bytes(boot);(target/'partitions.bin').write_bytes(table);(target/'otadata.bin').write_bytes(ota_data())
  size=by_name['spiffs']['size']
  if size not in fs_cache:fs_cache[size]=filesystem(size)
  fs=target/'littlefs.bin';fs.write_bytes(fs_cache[size]);offsets=[(0 if chip=='esp32s3' else 0x1000,target/'bootloader.bin'),(0x8000,target/'partitions.bin'),(0xe000,target/'otadata.bin'),(by_name['app0']['offset'],app_path),(by_name['app1']['offset'],app_path),(by_name['spiffs']['offset'],fs)]
  factory=target/'factory.bin';cmd=[sys.executable,'-m','esptool','--chip',chip,'merge_bin','--output',str(factory),'--flash_mode','dio','--flash_freq',freq,'--flash_size',f'{mb}MB','--target-offset','0x0','--fill-flash-size',f'{mb}MB']
  for offset,path in offsets:cmd.extend([hex(offset),str(path)])
  subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL)
  image=factory.read_bytes();assert len(image)==mb*1024*1024
  for offset,path in offsets:assert image[offset:offset+path.stat().st_size]==path.read_bytes(),path
  assert image[(0 if chip=='esp32s3' else 0x1000)+2]==2
  csv=ROOT/'partitions'/('esp32-4mb.csv' if mb==4 else f'esp32s3-{mb}mb.csv');part_hash=hashlib.sha256(csv.read_bytes()).hexdigest();assert part_hash in (b/'generated/build_info.h').read_text()
  update=target/f'Pocket_DNS_{version}.pdu';update.write_bytes(sign(app,a.key,chip,layout,part_hash,version,code));verify(update.read_bytes(),pub,chip,layout,part_hash,min_version=code)
  m={'chip':chip,'flash_size':f'{mb}MB','flash_frequency':freq,'factory':factory.relative_to(release).as_posix(),'signed_update':update.relative_to(release).as_posix(),'sha256':hashlib.sha256(image).hexdigest(),'bytes':len(image),'application_bytes':len(app),'partition_sha256':part_hash,'partitions':parts,'ram_static_bytes':None}
  manifest['boards'][layout]=m;print('Verified factory + both OTA slots + filesystem + signed update:',layout,len(app),'application bytes')
 (release/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');shutil.copy2(ROOT/'tools/flash.py',release/'flash.py');shutil.copy2(ROOT/'requirements-flash.txt',release/'requirements-flash.txt')
 from build_installer import build
 installer=build(release);print('Offline installer:',installer.stat().st_size,'bytes')
if __name__=='__main__':main()
