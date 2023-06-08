# ==========================================
# Usage:
# in the project root folder: ...../main/
# run: python3 scripts/getjar.py 
# This will update all related scripts: publisher.sh, prover.sh ... etc
# ==========================================

# get the jar import list
import subprocess;
import os;

# replace the -cp path
def process_script(filename, newline):
	srcfile = "scripts/templates/" + filename + ".template";
	dstfile = "scripts/" + filename + ".sh";
	f1 = open(srcfile, "r");
	s1 = f1.read();
	f1.close();
	s2 = s1.replace("J_ARDIR", newline)
	f2 = open(dstfile, "w");
	f2.write(s2);
	f2.close();

#MAIN PROGRAM	
LINE = "";
res = subprocess.run(["mvn", "dependency:build-classpath"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode('utf-8');
lines = res.split("\n");
for line in lines:
	#print("DEBUG USE 100: " + line);
	if line.find("jar")>=0 and line.find("spark")>=0:
		line = "target/zkregex-1.0-SNAPSHOT.jar:" + line;
		LINE = line;

# arr_scripts =["debug", "publisher", "profiler"]; 
arr_scripts =["prover", "publisher", "debug"];
for f in arr_scripts:
	process_script(f, LINE);
		

