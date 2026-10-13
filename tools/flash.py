#!/usr/bin/env python3
"""Detect ESP32/ESP32-S3, select the complete factory image and flash at 0x0."""
import argparse,hashlib,json,re,subprocess,sys,time
from pathlib import Path
import serial
from serial.tools import list_ports
ROOT=Path(__file__).resolve().parent

def choose(chip,mb):
 if chip=='esp32' and mb>=4:return 'esp32-4mb'
 if chip=='esp32s3':
  for size in [16,8,4]:
   if mb>=size:return f'esp32s3-{size}mb'
 raise ValueError('Supported: ESP32 and ESP32-S3 with at least 4 MB regular quad flash')
def read_setup(port,seconds=25):
 with serial.Serial(port,115200,timeout=.5) as conn:
  conn.dtr=False;conn.rts=False;deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   line=conn.readline().decode(errors='replace').strip()
   if not line.startswith('{'):continue
   try:d=json.loads(line)
   except ValueError:continue
   if d.get('pocketdns_setup')==2:
    print('\nSetup Wi-Fi:',d['ssid']);print('Setup password:',d['password']);print('Open:',d['url']);return True
 print('No setup credentials received. Press RESET once and run with --read-setup.');return False

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--port');p.add_argument('--read-setup',action='store_true');p.add_argument('--factory-reset',action='store_true',help='Acknowledge replacing firmware, Wi-Fi and settings');args=p.parse_args()
 port=args.port
 if not port:
  ports=list(list_ports.comports())
  if not ports:raise SystemExit('No serial port. Use a USB data cable; install CP210x driver if needed.')
  for i,x in enumerate(ports):print(f'{i+1}: {x.device} — {x.description}')
  port=ports[0].device if len(ports)==1 else ports[int(input('Select port number: '))-1].device
 if args.read_setup:read_setup(port);return
 if not args.factory_reset:
  answer=input('Factory install replaces firmware, Wi-Fi and settings. Type INSTALL to continue: ')
  if answer!='INSTALL':return
 cmd=[sys.executable,'-m','esptool','--port',port]
 detected=subprocess.run(cmd+['flash_id'],capture_output=True,text=True);text=detected.stdout+'\n'+detected.stderr
 if detected.returncode:raise SystemExit(text)
 if 'ESP32-S3' in text:chip='esp32s3'
 elif re.search(r'Chip is ESP32\b',text):chip='esp32'
 else:raise SystemExit('Unsupported chip. Do not flash a different family image.\n'+text)
 match=re.search(r'Detected flash size:\s*(\d+)MB',text)
 if not match:raise SystemExit('Flash capacity not detected.\n'+text)
 layout=choose(chip,int(match[1]));m=json.loads((ROOT/'manifest.json').read_text())['boards'][layout];image=ROOT/m['factory'];data=image.read_bytes()
 if len(data)!=m['bytes'] or hashlib.sha256(data).hexdigest()!=m['sha256']:raise SystemExit('Factory checksum mismatch; download the pack again.')
 print('Selected:',layout,'— full image at 0x0')
 subprocess.run(cmd+['--chip',chip,'--baud','460800','write_flash','--flash_mode','dio','--flash_freq',m['flash_frequency'],'--flash_size',m['flash_size'],'0x0',str(image)],check=True)
 try:read_setup(port)
 except serial.SerialException:print('USB reconnected. Run again with --read-setup, then press RESET.')
if __name__=='__main__':main()
