import sys,unittest,json,struct,hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sign_update import sign,verify,canonical
class SignedUpdateTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();root=Path(self.t.name);key=ec.generate_private_key(ec.SECP256R1());self.private=root/'private.pem';self.public=root/'public.pem';self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));self.binary=b'\xe9'+b'test firmware'*10000;self.data=sign(self.binary,self.private,'esp32','esp32-4mb','a'*64)
 def tearDown(self):self.t.cleanup()
 def test_valid_and_mismatch(self):
  self.assertEqual(verify(self.data,self.public,'esp32','esp32-4mb','a'*64)['bytes'],len(self.binary))
  for kw in [dict(chip='esp32s3'),dict(layout='esp32s3-8mb'),dict(partition_hash='b'*64),dict(min_version=20001)]:
   with self.assertRaises(Exception):verify(self.data,self.public,**kw)
 def test_tampered_image_and_header(self):
  for data in [self.data[:-1]+bytes([self.data[-1]^1]),self.data[:-100],self.data+b'extra',self.data[:8]+struct.pack('<I',3000)+self.data[12:],b'\0'*8+self.data[8:]]:
   with self.assertRaises(Exception):verify(data,self.public)
  size=struct.unpack('<I',self.data[8:12])[0];m=json.loads(self.data[12:12+size]);m['version_code']=20099;header=json.dumps(m).encode()
  with self.assertRaises(Exception):verify(self.data[:8]+struct.pack('<I',len(header))+header+self.binary,self.public)
 def test_untrusted_key(self):
  other=ec.generate_private_key(ec.SECP256R1());self.public.write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
  with self.assertRaises(Exception):verify(self.data,self.public)
if __name__=='__main__':unittest.main(verbosity=2)
