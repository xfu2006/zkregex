# -------------------------------------
# Dr. CorrAuthor
# Created: 12/14/2022
# Refined: 01/09/2022 -> added processing partitioned large files
# Refined: check the partition logic
#
# This file creates batch processing jobs
# NOTE: check the main() part for system parameters
# -------------------------------------

import re;
import math;
import os;

# return a dctionary
#    records of length in category 2^i, subset_id j
#    each record has attr: fpath, size (in kb), depth
# quota is quota limit at each SERVER! (total would be quota * servers)
def process_file(fname, subset_ids, np, job_dir, partition_size, quota, num_servers):
	f1 = open(fname, "r");
	arrLines = f1.readlines();
	f1.close()
	dict_all = {};

	total = 0;
	for line in arrLines:
		if line.find("FILEDUMP")==0:
			arr_rec = str_to_recs(line, partition_size);
			for rec in arr_rec:
				insert_rec(dict_all, rec, subset_ids, np);
				total += 1;
	gen_jobs(dict_all, job_dir, quota, num_servers);

def create_dir(sdir):
	import os;
	os.system("rm -fr " + sdir);
	os.system("mkdir -p " + sdir);

def get_file_size(fpath):
	try:
		file_size = os.path.getsize(fpath);
		return file_size;
	except: 
		print("FILE NOT EXIST: " + fpath);
		return -1;
	

# each job will be named as
# job_groupid_subsetid (e.g., job_10_20 for group 2^10 and subset id 20)
# quota of the /tmp2/batchprove folder. Note that the actual file size
# would have a multiplication factor of 1000. 
# Thus: 1M actual file -> 1000M data 
# quota input will would be quota at EACH SERVER
def gen_jobs(dict_all, sdir, quota_inp, servers):
	ratio = 4000; 
	quota = quota_inp/ratio * servers; #because files distributed over servers
	print("gen_jobs: quota: " + str(quota_inp) + " => limit total file input: " +str(quota));
	create_dir(sdir);
	for group_id in dict_all.keys():
		group_dicts = dict_all[group_id];
		for subset_id in group_dicts.keys():
			fname = "job_"+str(group_id)+"_"+str(subset_id) + ".txt";
			f1 = open(sdir+"/" +fname, "w");
			f1.write("#---- JOB LIST for size 2^"+str(group_id) + ", subset id: " + str(subset_id) + " ----\n#---- fpath filesize depth init_state end_state\n");
			arr = group_dicts[subset_id];
			total = 0;
			quota_id = 1;
			for rec in arr:
				filesize = rec["size"];
				line = rec["fpath"] + " " + str(filesize) + " " + str(rec["group_id"]) + " " + str(rec["offset"]) + " " + str(rec["depth"]) + " " + str(rec["start_state"]) + " " + str(rec["end_state"]) +  "\n";
				f1.write(line);
				total += filesize;
				if total>quota:
					fname = "job_"+str(group_id)+"_"+str(subset_id) + "_" + str(quota_id) + ".txt";
					print("QUOTA exceeded. Generate another job! Fname: " + fname); 
					f1.close();
					f1 = open(sdir+"/" + fname, "w");
					f1.write("#---- JOB LIST for size 2^"+str(group_id) + ", subset id: " + str(subset_id) + " ----\n#---- fpath filesize depth init_state end_state\n");
					total = 0;
					quota_id +=1;
			f1.close();

		


# get the number of partitions
def get_num_parts(fsize, partition_size):
	if fsize%partition_size==0:
		return fsize//partition_size;
	else:
		return fsize//partition_size + 1;

# get the partition size
def get_part_size(fsize, partition_size, idx):
	num_parts = get_num_parts(fsize, partition_size);
	start_idx = idx * partition_size;
	end_idx = (idx+1)* partition_size; #not included
	if end_idx>fsize: end_idx = fsize;
	new_len = end_idx - start_idx;
	return new_len;

def myassert(bval, msg):
	import sys;
	if not bval:
		print("ERROR: " + msg);
		sys.exit(1);	

# convert a string to a record OR MORE records if
# the file is partitioned
def str_to_recs(line, partition_size):
	#1. process the main file
	s_pat = "partitions_info: ";
	r1 = re.compile("FILEDUMP: (.*), Size: (.*), Group: (.*), .*good.*NewMaxDepth: ([0-9]+),.*init_state: ([0-9]+).*last_state: ([0-9]+).*");
	arr = r1.findall(line);
	if len(arr)>0 and len(arr[0])==6:
		depth = int(arr[0][3]);
		size = int(arr[0][1]);
		group_id = int(arr[0][2]);
		init_state = int(arr[0][4]);
		final_state = int(arr[0][5]);
	else:
		myassert(False, "ERROR in processing line: " + line);	

	#2. two cases: regular and multiple partitions
	if line.find(s_pat)==-1: #regular case
		obj = {"fpath": arr[0][0], "size": size, "group_id": group_id, "depth": depth, "start_state": init_state, "end_state": final_state, "offset": 0};
		return [obj];
	else:
		idx = line.find(s_pat) + len(s_pat) ;
		line_rest = line[idx:].strip();
		arr_num = line_rest.split();
		myassert(len(arr_num)%4==0," ERROR: len(arr_num)%3!=0! Details: " + str(arr_num));
		num_part = len(arr_num)//4;
		num_part2 = get_num_parts(size, partition_size);
		myassert(num_part==num_part2, "num_part: " + str(num_part) + " != num_part2: " + str(num_part2));
		res = [];
		last_state = 0;
		for u in range(num_part):
			depth = int(arr_num[4*u]);
			my_init_state = int(arr_num[4*u+1]);
			my_last_state = int(arr_num[4*u+2]);
			group_id = int(arr_num[4*u+3]);
			myassert(last_state==my_init_state, "last_state of last section: " + str(last_state) + " != my_init_state: " + str(my_init_state));
			part_size = get_part_size(size, partition_size, u);
			fpath = arr[0][0] + "_partx71_" + str(u);
			my_offset = u * partition_size;
			obj = {"fpath": fpath, "size": part_size, "depth": depth, "group_id": group_id, "start_state": last_state, "end_state": my_last_state, "offset": my_offset};
			last_state = my_last_state;
			res.append(obj);
		return res;

# insert record into dict_all
def insert_rec(dict_all, rec, subset_unit, np):
	#print("DEBUG USE 880: insert record: ", rec);
	size_group = rec["group_id"];
	size_group_2 = get_size_group(rec["size"], np);
	if size_group!=size_group_2:
		print("WARNING 504: size_group_2: " , size_group_2 , " != size_group: " , size_group, ". Check if this is caused by padding: " + rec["fpath"]);
	subset_id_group = get_subset_id(rec["depth"], subset_unit);
	if size_group not in dict_all.keys():
		group_rec = {};
		dict_all[size_group] = group_rec;
	group_rec = dict_all[size_group];
	if subset_id_group not in group_rec.keys():
		subset = [];
		group_rec[subset_id_group] = subset;
	subset = group_rec[subset_id_group];
	subset.append(rec);

# get its subset ID, assuming subset_unit in increasing order
def get_subset_id(depth, subset_unit):
	for subset_id in subset_unit: 
		if depth<=subset_id:
			return subset_id;
	# PANIC
	print("ERROR: depth: " + str(depth) + "greater than all subset_units!");
	x = 100/0;

# get the size limit for size group
def get_group_size(group_id, np):
	# need to be consistent with read_and_padd() of RustProver in main
	unit = 126;
	#cur_len = (2**group_id) * 2; # OLD one. now makes it slightly smaller
	# than 2^power so that when later rounded, it canbe rounded a one level
	# down in r1cs
	cur_len = (2**group_id) * 2 - unit * np;
	cur_len_per_node = cur_len//np;
	if cur_len_per_node%unit==0:
		target_len_per_node = cur_len_per_node;
	else:
		target_len_per_node = (cur_len_per_node//unit+1) * unit;
	#print("DEBUG USE 007: group_id: " + str(group_id) + ", np: " + str(np) + ", cur_len_per_node: " + str(cur_len_per_node) + ", target_len_per_node: " + str(target_len_per_node));
	target_len = target_len_per_node*np;
	min_len = unit * np;
	if target_len<min_len:
		target_len = min_len;
		#print("DEBUG USE 008: PAD to min_size: " + str(min_len));
	target_len = target_len//2; #convert back from nibbles to bytes
	#print("DEBUG USE 009: group_id: " + str(group_id) + ", np: " + str(np) + ", target_len: " + str(target_len));
	return target_len;

#get its group
def get_size_group(size, np):
	upper = int(math.log2(size)) + 5;
	for x in range(1, upper+1):
		if get_group_size(x, np)>size: 	
			return x;
	return -1;

#extract partition
def extract_partition_size(fpath):
	f1 = open(fpath, "r");
	lines= f1.readlines();
	f1.close();
	for line in lines:
		if line.find("PARTITION_SIZE")>=0:
			arrW = line.split();
			size = int(arrW[1]);
			return size;
	myassert(False, "unable to find PARTITION_SIZE!");

#----------------------------------
# MAIN
#----------------------------------
#set of subset_ids: NEEDS SAME as acc/RUN_CONFIG.subset_ids
SUBSET_IDS = [10, 15, 20, 30, 40, 50, 300]; 
#number of MPIC processes
NODES = 4;
SERVERS = 1; 
#file to process
file_all = "all.txt";
#quota in bytes for EACH server! (e.g., < disk consumption < 16GB each server)
quota = 1024*1024*1024*16; #16 GB
#quota = 1024*1024*1024*1; #1G

FILE_SIZE_LIMIT = extract_partition_size(file_all);
process_file(file_all, SUBSET_IDS, NODES, "jobs", FILE_SIZE_LIMIT, quota, SERVERS);
