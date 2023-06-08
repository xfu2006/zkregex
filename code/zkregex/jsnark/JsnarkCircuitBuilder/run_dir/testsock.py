import socket
import sys
from sage.all_cmdline import *   # import sage library
SHUTDOWN = False
HOST = 'localhost'
PORT = 8888
MAX_MSG_LENGTH = 102400
from cStringIO import StringIO

# Create socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print 'Socket created'

# Bind socket to localhost and port
try:
  s.bind((HOST, PORT))
except socket.error , msg:
  print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
  sys.exit()

print 'Socket bind complete'

# Start listening on socket
s.listen(10)
print 'Socket now listening'

# Loop listener for new connections
while not SHUTDOWN:
	conn, addr = s.accept()
	print 'Connected with ' + addr[0] + ':' + str(addr[1])

	# Receive message from client
  	msg = conn.recv(MAX_MSG_LENGTH)
	print(msg);
	sys.stdout = mystdout = StringIO()

	s1 = "p = 21888242871839275222246405745257275088548364400416034343698204186575808495617\n" + \
		"aa = 126932\n" + \
		"E = EllipticCurve(GF(p),[0,aa,0,1,0])\n" + \
		"pt1 = E(19825534823546879765673912400262438418055600219700522078383650029926939662322, 11564996723875128409420156802350032872695391840012938750766743977173010169599) \n" + \
		"print(pt1)\n";
	eval(compile(s1, '<cmdline>', 'exec'));
	result = mystdout.getvalue();
	sys.stdout = sys.__stdout__
	print("result is: " + result);
	conn.sendall(result);
	
	
