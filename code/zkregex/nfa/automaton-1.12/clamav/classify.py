# generate easy.dat medium.dat and hard.dat
# based on timeouts (see Datatypes.java in dk/bricks/automaton for details)

import subprocess
import multiprocessing
import os;

# return the output
# the arrcmd has the command and its output
def run_cmd(arrcmd):
	try:
		res = subprocess.check_output(arrcmd);
	except Exception:
		return "pass";

# exception throw
def panic(s):
	print("ERROR: " + s);
	os.exit(1);

def classify_regex(s):
	arr = ["java", "-Xmx100g", "-Xms4g", "-cp", "../target/automaton-1.12-4.jar", "dk.brics.automaton.Datatypes", "1", s];
	run_cmd(arr); # we know it will be killed
	res= open("result.txt", "r").read();
	if res.find("easy")>=0:
		return "easy";
	elif res.find("medium")>=0:
		return "medium";
	elif res.find("hard")>=0:
		return "hard";
	else:
		panic("could not find level: " + res);


def writearr(arr, fname):
	n = len(arr);
	f1 = open(fname, "w");
	for i in range(n):	
		if i<n-1:
			f1.write(arr[i]);
		else:
			f1.write(arr[i]);
	f1.close();

# proess the file and split into three files
def process_file(filename, MAX):
	f1  = open(filename);
	arrlines = f1.readlines();
	n = len(arrlines);
	f1.close();

	arrEasy = [];
	arrMed = [];
	arrHard = [];
	i = 0;
	for line in arrlines:
		print("processing line " + str(i) + " ...");
		level = classify_regex(line);
		print("RESULT: " + level);
		if level =="easy":
			arrEasy.append(line);
		elif level =="medium":
			arrMed.append(line);
		elif level=="hard":
			arrHard.append(line);
		else:
			panic("UNKNOWN LEVEL: " + level);
		if i>MAX:
			break;
		i+=1;	
	writearr(arrEasy, "easy.dat");
	writearr(arrMed, "medium.dat");
	writearr(arrHard, "hard.dat");
	print("easy: " + str(len(arrEasy)) + ", medium: " + str(len(arrMed)) + ", hard: " + str(len(arrHard)));

# MAIN
process_file("regex1.dat", 8720);
	
