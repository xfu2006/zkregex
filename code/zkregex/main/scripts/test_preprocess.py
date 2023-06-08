# -----------------------------
# test preprocess
# mainly to check if run_checks padding is ok
# useage: python3 test_preprocess.py > dump.txt &
# -----------------------------

import os;
import subprocess;

def get_all_jobs(job_dir):
	files = os.listdir(job_dir);
	res = [];
	for x in files:
		res.append(job_dir + "/" + x);
	return res;

def run_cmd(cmd):
#	arr = cmd.split();
#	proc = subprocess.Popen(arr, stdout=subprocess.PIPE, shell=True)
#	(out, err) = proc.communicate();
#	sout = out + err;
	sout = os.popen(cmd).read();
	print(sout);
	return sout;

# run job file and with num_worker of threads	
# return the analysis result
def run_job(job_file, num_worker):
	f1 = open("scripts/test_preprocess_cmd.txt");
	print("processing: " + job_file + " ...");
	cmd = f1.read();
	f1.close(); 
	cmd = cmd.replace("JOB1100", job_file);
	cmd = cmd.replace("WORKER1100", str(num_worker));
	#print(cmd);
	res = run_cmd(cmd);
	print(res);
	analysis = analyze_output(res);
	return analysis;

def get_all_execs(job_file):
	jobs = get_all_jobs(job_file);
	res = [];
	for job_file in jobs:
		f1 = open(job_file, "r");
		arrlines = f1.readlines();
		f1.close();
		for line in arrlines:
			line = line.strip();
			if line.find("#")==0: continue;
			arr = line.split();
			fname = arr[0];
			res.append(fname);
	return res;

# return [set_of_goodfiles, set_of_fails, set_of_warnings]
def analyze_output(sout):
	lines = sout.split("\n");
	res_good = [];
	res_fail = [];
	res_warn = [];
	for line in lines:
		if line.find("SUCCESS_Preprocess:")>=0:
			fpath= line.split()[3];
			res_good.append(fpath);
		if line.find("WARNING 502")>=0:
			res_warn.append(line);
		if line.find("ERROR 501")>=0:
			res_fail.append(line);
	return [res_good, res_fail, res_warn];

def get_diff(set1, set2):
	res = [];
	for x in set1:
		if not x in set2:
			res.append(x);
	return res;

# ------------------------
# MAIN
# ------------------------
#job_file = "../acc/batchscripts/jobs_2";
job_file = "../acc/batchscripts/jobs";
jobs = get_all_jobs(job_file);
num_worker = 4;
res_good = [];
res_fail = [];
res_warn = [];
for job in jobs:
	res = run_job(job, num_worker);
	res_good += res[0];
	res_fail+= res[1];
	res_warn+= res[2];
execs = get_all_execs(job_file);

print("res_good: " , res_good);
print("res_fail: " , res_fail);
print("res_warn: " , res_warn);
missing = get_diff(execs, res_good);
print("==================\n Failed Files ================");
for x in missing:
	print(x);
print("=============== Summary: ===================");
print("Good: ", len(res_good));
print("Reported Fail: ", len(res_fail));
print("Reported Warn: ", len(res_warn));
print("Missing (Failed): ", len(missing));

