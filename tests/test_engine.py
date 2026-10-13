import socket,struct,threading,time,subprocess,os,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def query(domain,ident=123,edns=False):
 q=struct.pack('!6H',ident,0x100,1,0,0,int(edns))+b''.join(bytes([len(l)])+l.encode() for l in domain.split('.'))+b'\0'+struct.pack('!HH',1,1)
 if edns:q+=b'\0'+struct.pack('!HHIH',41,1232,0,4)+struct.pack('!HH',10,0)
 return q
def question_end(q):
 p=12
 while q[p]:p+=q[p]+1
 return p+5
def domain(q):
 p=12;parts=[]
 while q[p]:n=q[p];p+=1;parts.append(q[p:p+n].decode());p+=n
 return '.'.join(parts)
def answer(q,large=False):
 end=question_end(q);ident=struct.unpack('!H',q[:2])[0];head=struct.pack('!6H',ident,0x8180,1,1 if not large else 41,0,0)
 if large:return head+q[12:end]+(b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+b'\1\2\3\4')*41
 return head+q[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,1 if domain(q)=='expiry.test' else 60,4)+b'\1\2\3\4'
def free_port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
class Upstream:
 def __init__(self,ip,port,primary):
  self.ip=ip;self.port=port;self.primary=primary;self.counts={};self.running=True
  self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind((ip,port));self.udp.settimeout(.1)
  self.tcp=socket.socket();self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.tcp.bind((ip,port));self.tcp.listen();self.tcp.settimeout(.1)
  self.threads=[threading.Thread(target=self.udp_loop),threading.Thread(target=self.tcp_loop)]
  for t in self.threads:t.start()
 def udp_loop(self):
  while self.running:
   try:q,addr=self.udp.recvfrom(8192)
   except socket.timeout:continue
   except OSError:return
   d=domain(q);self.counts[d]=self.counts.get(d,0)+1
   if self.primary and d in ['timeout.test','queue.test']:continue
   if self.primary and d=='large.test':a=bytearray(q[:question_end(q)]);a[2]=0x83;a[3]=0x80
   elif self.primary and d=='bad.test':a=answer(q)[:-1]
   elif self.primary and d=='spoof.test':
    a=bytearray(answer(q));a[0]^=3;self.udp.sendto(a,addr);a=answer(q)
   else:a=answer(q)
   if self.primary and d.startswith('concurrent'):
    threading.Timer(.04-int(d[10])*0.004,lambda a=a,addr=addr:self.udp.sendto(a,addr)).start()
   else:self.udp.sendto(a,addr)
 def tcp_loop(self):
  while self.running:
   try:c,_=self.tcp.accept()
   except socket.timeout:continue
   except OSError:return
   threading.Thread(target=self.tcp_client,args=(c,)).start()
 def tcp_client(self,c):
  c.settimeout(1)
  try:
   h=recv_exact(c,2);q=recv_exact(c,struct.unpack('!H',h)[0]);a=answer(q,domain(q)=='large.test');fr=struct.pack('!H',len(a))+a
   c.sendall(fr[:1]);time.sleep(.005);c.sendall(fr[1:9]);time.sleep(.005);c.sendall(fr[9:])
  finally:c.close()
 def close(self):
  self.running=False
  for t in self.threads:t.join(2)
  self.udp.close();self.tcp.close()
def recv_exact(s,n):
 out=b''
 while len(out)<n:
  b=s.recv(n-len(out))
  if not b:raise RuntimeError('EOF')
  out+=b
 return out
class EngineTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.port=free_port();cls.up_port=free_port();cls.primary=Upstream('127.0.0.1',cls.up_port,True);cls.backup=Upstream('127.0.0.2',cls.up_port,False)
  cls.process=subprocess.Popen([str(ROOT/'tests/engine_host'),str(cls.port),str(cls.up_port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
  assert cls.process.stdout.readline().strip()=='READY'
 @classmethod
 def tearDownClass(cls):
  cls.process.terminate();out,err=cls.process.communicate(timeout=5);cls.primary.close();cls.backup.close();print(out.strip());assert cls.process.returncode==0,err
 def udp(self,d,ident=123,edns=False):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(query(d,ident,edns),('127.0.0.1',self.port));a=s.recv(8192);s.close();self.assertEqual(struct.unpack('!H',a[:2])[0],ident);return a
 def test_blocked(self):
  a=self.udp('blocked.test');self.assertEqual(a[-4:],b'\0'*4);self.assertNotIn('blocked.test',self.primary.counts)
 def test_cache_and_expiry(self):
  self.udp('expiry.test');self.udp('expiry.test',777);self.assertEqual(self.primary.counts['expiry.test'],1);time.sleep(1.1);self.udp('expiry.test');self.assertEqual(self.primary.counts['expiry.test'],2)
 def test_backup_timeout_and_malformed(self):
  for d in ['timeout.test','bad.test']:
   self.assertEqual(self.udp(d)[-4:],b'\1\2\3\4');self.assertGreater(self.backup.counts[d],0)
 def test_spoof_id(self):self.assertEqual(self.udp('spoof.test')[-4:],b'\1\2\3\4')
 def test_concurrent(self):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
  for i in range(6):s.sendto(query(f'concurrent{i}.test',1000+i),('127.0.0.1',self.port))
  seen={}
  for _ in range(6):a=s.recv(8192);seen[struct.unpack('!H',a[:2])[0]]=domain(a)
  self.assertEqual(seen,{1000+i:f'concurrent{i}.test' for i in range(6)});s.close()
 def test_tcp_and_truncation(self):
  a=self.udp('large.test');self.assertTrue(a[2]&2)
  s=socket.create_connection(('127.0.0.1',self.port));s.settimeout(2)
  for ident in [301,302]:
   q=query('large.test',ident);f=struct.pack('!H',len(q))+q;s.sendall(f[:1]);time.sleep(.005);s.sendall(f[1:]);a=recv_exact(s,struct.unpack('!H',recv_exact(s,2))[0]);self.assertEqual(a[:2],struct.pack('!H',ident));self.assertFalse(a[2]&2);self.assertGreater(len(a),512)
  s.close()
 def test_option_queries_not_cached(self):
  self.udp('cookie.test',1,True);self.udp('cookie.test',2,True);self.assertEqual(self.primary.counts['cookie.test'],2)
 def test_queue_overload_recovers(self):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
  for i in range(10):s.sendto(query('queue.test',2000+i),('127.0.0.1',self.port))
  replies=[s.recv(8192) for _ in range(10)];self.assertEqual(len({r[:2] for r in replies}),10);self.assertTrue(any(r[3]&15==2 for r in replies));s.close();self.assertEqual(self.udp('recovered.test')[-4:],b'\1\2\3\4')
if __name__=='__main__':unittest.main(verbosity=2)
