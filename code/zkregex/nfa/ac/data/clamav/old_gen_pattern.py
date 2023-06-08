# ---------------------
# Dr. CorrAuthor, Friday 03/26/2022
# Modified 08/31/2022 -> refactored desgin
# extract fixed pattersn
# ---------------------

from re import *;

# remove special chars
def filter_str(s):
	s1 = s + "";
	s1 = s1.replace("*", "");
	s1 = s1.replace(",", "");
	s1 = s1.replace("{", "");
	s1 = s1.replace("}", "");
	s1 = s1.replace("(", "");
	s1 = s1.replace(")", "");
	s1 = s1.replace("[", "");
	s1 = s1.replace("]", "");
	s1 = s1.replace("|", "");
	s1 = s1.replace("?", "");
	s1 = s1.replace("-", "");
	return s1;

# process the src_file and write info to dest_file
# a siganture is a collection of patterns connected by operators
# one signature is one virus
def process(src_file, dest_file):
	f1 = open(src_file, "r");
	f2 = open(dest_file, "w");
	n = 0; #total signatures
	n_reg = 0; #total signatures with regular operators
	n_dropped = 0; #total signatures with dropped patterns

	arrLines = f1.readlines();
	r1 = re.compile("\*|,|{.*?}|\(.*?\)|\?+");
	for line in arrLines:
		#1. split line by operators
		arrWords = re.split(r1, line);
		arr
		#2. remove patterns if too short
		
		#3. write to file 
		


for line in arrLines:
	arr = line.split(":");
	s_old = arr[-1] + "";
	n += 1;
	s1 = arr[-1];
	s1 = s1.replace("*", "");
	s1 = s1.replace(",", "");
	s1 = s1.replace("{", "");
	s1 = s1.replace("}", "");
	s1 = s1.replace("(", "");
	s1 = s1.replace(")", "");
	s1 = s1.replace("[", "");
	s1 = s1.replace("]", "");
	s1 = s1.replace("|", "");
	s1 = s1.replace("?", "");
	s1 = s1.replace("-", "");
	if len(s1)>10:
		f2.write(s1);
	if s1!=s_old:
		n_reg += 1;
	
f1.close();
f2.close();
print("ALL: ", n , "regex: ", n_reg);

# MAIN
process("source/main.ndb", "fixed_new.dat");
