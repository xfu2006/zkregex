# -------------------------------------
# Author: CorrAuthor
# Created: 12/28/2022
#
# Used for debugging the gen_vars() function 
# -------------------------------------

# return a map
def read_vars(fpath):
	f1 = open(fpath, "r");
	arr_lines = f1.readlines();
	f1.close();
	my_dict = {};

	b_start = False;	
	for line in arr_lines:
		if line.find("assignments")>=0:
			b_start = True;
			continue;
		if line.find("constraints")>=0:
			b_start = False;
		if b_start:
			arr_words = line.split();
			if len(arr_words)!=2:
				print("ERRROR processing line: " + line);
				1/(100-100);
			var_id = int(arr_words[0]);
			var_val = int(arr_words[1]);
			my_dict[var_id] = var_val;
	return my_dict;

def diff_set(set1, set2):
	for key in set2:
		if set1[key] !=set2[key]:
			print("FAIL at: " + str(key) + ", set1: " + str(set1[key]) + ", set2: " + str(set2[key]));
			return;

# MAIN
for u in range(4):
	#fr1cs = "circuits/11223344/"+str(u)+"/ModularTraceVerifier_Bls381_Poseidon.r1cs.Bls381";
	fvars= "circuits/11223344/"+str(u)+"/vars.txt";
	fvars2= "circuits/11223344/"+str(u)+"/vars2.txt";
	dict1 = read_vars(fvars);
	dict2 = read_vars(fvars2);
	print("============ CHECKING now ===========");
	if dict1!=dict2:
		diff_set(dict1, dict2);
		diff_set(dict2, dict1);
	print("me: " + str(u) + ",  dict1 size: " + str(len(dict1)) + ", dict2 size: " + str(len(dict2)));
	print("============ CHECKING complted ===========");
 
