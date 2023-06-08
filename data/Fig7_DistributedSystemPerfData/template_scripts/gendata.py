# -------------------------------
# emulate the data generation
# -------------------------------

from random import *;
from numpy.random import seed
from numpy.random import normal
from numpy.random import poisson 
import re;

OUTPUT_DIR = "../raw_data/";

# write 2 dimensional array into given file
def write_2darr_to_file(arr2d, fname):
	f = open(OUTPUT_DIR + fname, "w");
	for row in arr2d:
		line = "";
		for x in row:
			s = str(x) + "\t";
			line += s;
		line += "\n";
		f.write(line);	
	f.close();	

def write_1darr_to_file(arr1d, fname):
	f = open(OUTPUT_DIR + fname, "w");
	for x in arr1d:
		line = str(x) + "\n";
		f.write(line);	
	f.close();	

# generate fig_exec(a,b,c)
# parse the full scan of linux ubuntu ELF files
# return 2d array of
# [fname, size_in_kb, new_max_depth]
def gen_fig_execs():
	f1 = open("../run_dumps/full_scan.dump", "r");
	arrlines = f1.readlines();
	f1.close();
	data = [];
	for line in arrlines:
		if line.find("FILEDUMP")>=0:
			arr = line.split(",");
			rec = [arr[0].split(":")[1], int(arr[1].split(":")[1].split(" ")[1]), int(arr[5].split(":")[1])];
			data.append(rec);

	#1. writing data 
	write_2darr_to_file(data, "fig_exec.dat");

	#2. getting the average, min, and max size
	imin = 999999999999999999999999999;
	imax = 0;
	total = 0;
	for row in data:
		fname = row[0];
		size = row[1];
		total += size;
		if size>imax:
			imax = size;
			max_file = fname;
		if size<imin:
			imin = size;
			min_file = fname;
	print("Files: " + str(len(data)) +  ", Total Size: " + str(total/1024) + " MB" + ", MaxFile: " + max_file + " " + str(imax/1024) + " MB" + ", Avg size: " + str(total/len(data)) + " kb"); 

	#3. process the distribution of depth
	#every entry represents a chunk of 10, e.g., count[0] represents 0 to 10
	arr_depth_cost = [];
	for line in arrlines:
		if line.find("Depth ")==0 and len(arr_depth_cost)<200:
			val = float(line.split()[2]);
			arr_depth_cost.append(val);
		if line.find("ratio among states")>=0:
			val = re.findall("ratio among states: (.*)%", line);
			val = float(val[0]);
	for idx in range(len(arr_depth_cost)):
		arr_depth_cost[idx] += val;

	count = [0] * 30; 
	total_depth = 0;
	max_depth = 0;
	for row in data:
		depth = row[2];
		total_depth += depth;
		chunk_depth = depth//10;
		count[chunk_depth] += 1;
		if depth>max_depth:
			max_depth = depth;
			max_file = row[0];

	for idx in range(len(count)-1):
		count[idx+1] += count[idx];
	for idx in range(len(count)):
		count[idx] = count[idx]/len(data) * 100.0;
	for idx in range(19):
		s_perc = "%.2f%%" % (count[idx]);
		print( " < " + str((idx+1)*10) + ": " + s_perc + ", cost: " + str(arr_depth_cost[(idx+1)*10])[0:5]+"%");
	print("Max Depth: " + str(max_depth) + "at file: " + max_file + ", Avg Depth: " + str(total_depth/len(data)));
	print("COUNT of files: " + str(len(data)));

# extract a collection of records from a given file
# generate records <op, size, time, np>
# time is in ms
def extract_records(fname):
	f1 = open(fname, "r");
	arrlines = f1.readlines();
	f1.close();

	arrRec = [];
	for line in arrlines:
		if line.find("REPORT_")==0: #process it
			arr = line.split(",");
			rec = {};
			for item in arr:
				a1 = item.split(":");
				skey = a1[0].strip();
				if skey.find("REPORT_")>=0:
					skey = skey[7:];
				val = a1[1].strip().split()[0];
				if val.isnumeric():
					rec[skey] = int(val);
				else:
					rec[skey] = val;
			arrRec.append(rec);
	return arrRec;

# return all values in sorted (ascending)
def get_sorted(arrRecs, opname, skey):
	arr = [];
	for rec in arrRecs:
		if opname==rec["op"]:
			val = rec[skey];
			if not val in arr:
				arr.append(val);
	arr.sort();
	return arr;

# given the opname, size and np retrieve the time
# slow (but ok for smaller data set)
def get_time(arrRec, opname, size, np):
	for rec in arrRec:
		if rec["op"]==opname and rec["size"]==size and rec["np"]==np:
			return rec["time"];
	print("CANNOT find record for: " + opname + ", size: " + str(size) + ", np: " + str(np));

# extract all records of the op
# write a 2-dimensioal table into fname
def write_recs(arrRecs, opname, fname):
	arr_np = get_sorted(arrRecs, opname, "np");
	arr_size = get_sorted(arrRecs, opname, "size");

	title_row = ["SIZE/np"] + arr_np;
	data2d = [title_row];	
	for size in arr_size:
		row = [size];
		for np in arr_np:
			itime = get_time(arrRecs, opname, size, np);
			row.append(itime);
		data2d.append(row);

	write_2darr_to_file(data2d, fname);	
		

		

def main():
	#gen_fig_execs();
	#arr_rec = extract_records("../run_dumps/poly.dump");
	#arr_rec = extract_records("../run_dumps/poly_op_bigdata.dump");
	#arr_rec = extract_records("../run_dumps/fft_hpc256_12212022.dump");
	arr_rec = extract_records("../run_dumps/fft_hpc256_01062023.dump");
	arr_rec2 = extract_records("../run_dumps/mul_hpc256_12262022.dump");
	arr_rec3 = extract_records("../run_dumps/div_02_23_23.dump");
	arr_rec4 = extract_records("../run_dumps/groth16_full_singlethread.dump");
	write_recs(arr_rec, "fft", "../raw_data/fft_hpc256.dat");
	write_recs(arr_rec2, "mul", "../raw_data/mul_hpc256.dat");
	write_recs(arr_rec3, "div", "../raw_data/div_hpc256.dat");
	write_recs(arr_rec4, "groth16prove", "../raw_data/groth_hpc256.dat");
	

main();
	



