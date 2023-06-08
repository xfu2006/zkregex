# ---------------------
# Dr. CorrAuthor, Friday 03/26/2022
# Modified 08/31/2022 -> refactored desgin
# extract fixed pattersn
# ---------------------

import re;
def extract_false_positive_patterns():
	arr_set = [];
	files = [
		"false_positives/data1.txt",
		"false_positives/data2.txt",
		"false_positives/data3.txt",
		"false_positives/data4.txt",
		"false_positives/data5.txt",
		"false_positives/data6.txt",
		"false_positives/data7.txt",
		"false_positives/data8.txt",
		"false_positives/data9.txt",
		"false_positives/data10.txt",
		"false_positives/data11.txt",
		"false_positives/data12.txt",
		"false_positives/data13.txt",
		"false_positives/data14.txt",
		"false_positives/data15.txt",
		"false_positives/data16.txt",
		"false_positives/data17.txt",
		"false_positives/data18.txt",
		"false_positives/data19.txt",
		"false_positives/data20.txt",
		"false_positives/data21.txt",
		"false_positives/data22.txt",
		"false_positives/data22.txt",
		"false_positives/data23.txt",
		"false_positives/data24.txt",
		"false_positives/data25.txt",
		"false_positives/data26.txt",
		"false_positives/data27.txt",
		"false_positives/data28.txt",
		"false_positives/data29.txt",
		];
	#files = ["false_positive.txt"];
	for file in files:
		extract_false_positive_patterns_worker(file, arr_set);
		print("AFTER prcessing file: " + file + ", arr_set size: " , len(arr_set));
	return arr_set;

def extract_false_positive_patterns_worker(file, arr_set):
	f1 = open(file, "r");
	arrlines = f1.readlines();
	r1 = re.compile("pattern: (.*),.*");
	for line in arrlines:
		sarr = r1.findall(line);
		if len(sarr)==1:
			pat = sarr[0].strip().lower();
			if pat not in arr_set:
				arr_set.append(pat);
		elif len(sarr)>1:
			print("ERROR on extract patterns: ", sarr);
			x = 200/(2-2);
	print("FALSE POSITIVE PATTRENS: ", len(arr_set));
	return arr_set;


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

def is_high_freq(s):
	dict = {};
	for x in s:
		if x in dict:
			dict[x] = dict[x] + 1;
		else:
			dict[x] = 1;
	for x in dict.keys():
		if dict[x]*1.0/len(s) >0.8: return True;
	return False;

def is_high_freq2(s):
	dict = {};
	for idx in range(0,len(s)-2, 2):
		x = s[idx:idx+2];
		if x in dict:
			dict[x] = dict[x] + 1;
		else:
			dict[x] = 1;
	for x in dict.keys():
		if dict[x]*2.0/len(s) >0.8: return True;
	return False;

# skip some regex patterns that triggers false alarms (can't be ruled 
# out by length)	
def is_special_pattern(s, patterns):
	return s in patterns;

# process the src_file and write info to dest_file
# a siganture is a collection of patterns connected by operators
# one signature is one virus
def process(src_file, dest_file):
	MIN_LEN = 20;
	MIN_LEN_REG = 20;
	f1 = open(src_file, "r");
	f2 = open(dest_file, "w");
	f2.close();
	f2 = open(dest_file, "a");
	n = 0; #total signatures
	n_reg = 0; #total signatures with regular operators
	n_dropped = 0; #total signatures with dropped patterns
	n_pats = 0; #total number of patterns;
	n_empty_pats = 0; #empty patterns due to drop

	arrLines = f1.readlines();
	extra_patterns = extract_false_positive_patterns();
	bad_patterns = [];
	short_bad_patterns = [];
	for upat in extra_patterns:
		if upat not in bad_patterns: bad_patterns.append(upat);
	r1 = re.compile("\*|,|\[.*?\]|{.*?}|\(.*?\)|\?+");
	for line in arrLines:
		#1. get the pattern
		arr = line.split(":");
		sig = arr[3];
		n+=1;

		#1. split line by operators
		sig= sig.strip();
		arrWords = re.split(r1, sig);
		if len(arrWords)>1: n_reg+=1;
		new_arr = [];
		bDropped = False;
		w_zeros = "0"*24;
		for w in arrWords:
			w = w.lower();
			if filter_str(w)!=w:
				#print("ERROR: w not well formed: " + w);
	#			ERR = 100/(2-2);
				bDropped = True;
				if w not in bad_patterns: bad_patterns.append(w);
			elif len(arrWords)>1 and is_high_freq(w):
				#print("DROPPING high freq word: " + w + ", len(w): ", len(w), "len(arrWords)", len(arrWords));
				bDropped = True;
				if w not in bad_patterns: bad_patterns.append(w);
			elif len(arrWords)>1 and is_high_freq2(w):
				#print("DROPPING high freq2 word: " + w + ", len(w): ", len(w), "len(arrWords): ", len(arrWords));
				bDropped = True;
				if w not in bad_patterns: bad_patterns.append(w);
			elif len(arrWords)>1 and len(w)<MIN_LEN_REG:
				#print("DROPPING short words: " + w);
				bDropped = True;
				if w not in bad_patterns: bad_patterns.append(w);
				if w not in short_bad_patterns: short_bad_patterns.append(w);
			elif is_special_pattern(w, extra_patterns):
				bDropped = True;
			else:
				if len(w)>MIN_LEN:
					new_arr.append(w);
				#else: print("DROPPING: " + w);
		if bDropped: n_dropped+=1;
		
		#3. write to file 
		n_pats += len(new_arr);
		for w in new_arr:
			f2.write(w + "\n"); 
		if len(new_arr)==0:
			#print("WARNING: all patterns dropped! ");
			#print("LINE is: " + line);
			n_empty_pats+=1;
	# print stats
	print("======= Summary ==========");
	print("Signatures: ", n);
	print("Regex Sigs: ", n_reg);
	print("Regex Sigs with Dropped: ", n_dropped);
	print("Bad Patterns Discarded: ", len(bad_patterns));
	print("Short Bad Patterns Discarded (included above): ", len(short_bad_patterns));
	print("False Positive Patterns (included in BadBatterns): ", len(extra_patterns));
	print("Empty Patterns: ", n_empty_pats);
	print("Total Patterns: ", n_pats);

# MAIN
process("source/main.ndb", "fixed_new.dat");
