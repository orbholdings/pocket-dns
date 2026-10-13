#!/usr/bin/env python3
"""Create/verify Pocket DNS signed OTA packages. Private key stays outside source."""
import argparse,hashlib,json,struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
MAGIC=b'PDNS2UPD'
def canonical(m):
 return ('PocketDNS update v2\n'+'\n'.join(str(m[k]) for k in ['chip','layout','partition_sha256','version','version_code','bytes','sha256'])+'\n').encode()
def sign(binary,private,chip,layout,partition_hash,version='2.0.0',version_code=20000):
 m={'chip':chip,'layout':layout,'partition_sha256':partition_hash,'version':version,'version_code':version_code,'bytes':len(binary),'sha256':hashlib.sha256(binary).hexdigest()}
 key=serialization.load_pem_private_key(Path(private).read_bytes(),None)
 if not isinstance(key,ec.EllipticCurvePrivateKey) or key.curve.name!='secp256r1':raise ValueError('Expected an ECDSA P-256 private key')
 m['signature']=key.sign(canonical(m),ec.ECDSA(hashes.SHA256())).hex();header=json.dumps(m,separators=(',',':')).encode();assert len(header)<=2048
 return MAGIC+struct.pack('<I',len(header))+header+binary

def verify(data,public,chip=None,layout=None,partition_hash=None,min_version=20000):
 if data[:8]!=MAGIC or len(data)<12:raise ValueError('Bad update magic')
 n=struct.unpack_from('<I',data,8)[0]
 if not 128<=n<=2048 or len(data)<12+n:raise ValueError('Bad manifest length')
 m=json.loads(data[12:12+n]);binary=data[12+n:]
 if len(binary)!=m['bytes'] or hashlib.sha256(binary).hexdigest()!=m['sha256']:raise ValueError('Image checksum/length mismatch')
 if chip and m['chip']!=chip or layout and m['layout']!=layout or partition_hash and m['partition_sha256']!=partition_hash:raise ValueError('Board/layout mismatch')
 if m['version_code']<min_version:raise ValueError('Downgrade rejected')
 key=serialization.load_pem_public_key(Path(public).read_bytes());key.verify(bytes.fromhex(m['signature']),canonical(m),ec.ECDSA(hashes.SHA256()));return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--key',type=Path,required=True);p.add_argument('--chip',choices=['esp32','esp32s3'],required=True);p.add_argument('--layout',required=True);p.add_argument('--partitions',type=Path,required=True);p.add_argument('--version',default='2.0.0');p.add_argument('--version-code',type=int,default=20000);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.write_bytes(sign(a.firmware.read_bytes(),a.key,a.chip,a.layout,hashlib.sha256(a.partitions.read_bytes()).hexdigest(),a.version,a.version_code));print('Signed package written:',a.output)
if __name__=='__main__':main()
