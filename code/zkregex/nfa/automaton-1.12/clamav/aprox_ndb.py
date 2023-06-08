# Author: Dr. CorrAuthor
# Created Monday 03/21/2022
# This file extracts regex from main.ndb from clamav set

import os;

# if s is a regex in clamav pattern
def isRegex(s):
	return s.find("[")>=0 or s.find("*")>=0 or s.find("{")>=0;

# handle this due to Java compiler preprocessor sensitive to
# "\u000A", "\u000D" .
# They should be translated to "\n" and "\r"
# Otherwise appending "\u000" to the single letter
# assumption: s is "0" to "9" or "a" to "f" 
def getUnicode(s):	
	if s>="0" and s<="9":
		return "\\u000"+s;
	elif s=="a":
		return "\\n";
	elif s=="b" or s=="c" or s=="e" or s=="f":
		return "\\u000" + s;
	elif s=="d":
		return "\\r";
	else:
		panic("cannot process unicode: " + s);
 

def panic(s):
	print("ERROR: " + s);
	os.exit(1);

#returning the standard regex
def to_standard_regex(name, s):
	s = s.lower();
	s2 = "";
	s = s.replace("{-", "{0-");
	s = s.replace("-}", "}*");
	s = s.replace("\n", "");
	curve_mode = False;
	for x in s:
		if curve_mode==False:
			if x>="0" and x<="9" or x>="a" and x<="f":
				s2 += getUnicode(x);
			elif x=="{":
				curve_mode = True;
				s2 += "." + x;
			elif x=="[" or x=="]" or x=="|" or x=="(" or x==")":
				s2 += x;
			elif x=="*":
				s2 += "." + x;
			elif x=="?":
				s2 += ".";
			else:
				panic("ERROR in " + name + ": can't process " + x + "\n, current line is: " + s);
		else:
			if x>="0" and x<="9" or x>="a" and x<="f":
				s2 += x;
			elif x=="-":
				s2 += ",";
			elif x=="}":
				s2 += x;
				curve_mode = False;
			else:
				panic("ERROR2 in " + name + ": can't process " + x);
	return s2;

#replace ach {.*} with .*
import re;
def approx(s):
	s2 = re.sub(r'.{.*?}', ".*", s);
	return s2;
	


#return an array of regex
def process_file(filename):
	print("process " + filename + " ...");
	f1 = open(filename);
	arrlines = f1.readlines();
	arr = [];
	for line in arrlines:
		arrwords = line.split(":");
		s = arrwords[-1];
		name = arrwords[0];
		if isRegex(s):
			#print(s);
			s2 = to_standard_regex(name, s);
			s2 = approx(s2);	
			arr.append(s2);
	f1.close();
	return arr;

# write results
def write_to_file(arr, filename):
	f1 = open(filename, "w");
	for s in arr:
		f1.write(s + "\n");
	f1.close();


#MAIN
arr = process_file("main.ndb");
#arr = process_file("test.ndb");
write_to_file(arr, "regex2.dat");
print("regex #: " + str(len(arr)));
