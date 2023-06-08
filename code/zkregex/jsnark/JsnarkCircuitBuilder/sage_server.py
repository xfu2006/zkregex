# ----------------------------------------------
# Author:  Dr. CorrAuthor
# Created: 05/22/2021
# Idea from: https://ask.sagemath.org/question/23431/running-sage-from-other-languages-with-higher-performance/
# Run: sage sage_server.py. It will listen at port 9999
# Utils.java has run_sage() function to interact as a TCP client
# NOTE: UNSAFE in multi-thread mode as it's reading from test001.sage
#   to improve later but not urgent at this moment.
# ----------------------------------------------- 

import socket;
import sys;
from sage.all_cmdline import *   
from cStringIO import StringIO;
#from io import StringIO; # for Python > 3.8

#1. Create server and binding
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);

try:
  sock.bind(("localhost", 9999))
except socket.error as msg:
  print("Bind failed: " + msg);
  sys.exit()
print("Sage Server Listening ...");

sock.listen(10);
while True:
	#1. prepare stdout for redir of result
	conn, addr = sock.accept();
  	msg = conn.recv(1000); 
	sys.stdout = mystdout = StringIO()

	#2. run and collect result
	f1 = open("run_dir/test001.sage");
	s1 = f1.read();
	f1.close();
	eval(compile(s1, '<cmdline>', 'exec'));
	result = mystdout.getvalue();
	sys.stdout = sys.__stdout__
	result = result.encode();
	conn.sendall(result);
	
	
