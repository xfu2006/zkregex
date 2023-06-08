# 03/21/2023
# Dr. CorrAuthor
# read the list.txt and create the data directory

import os;

def create_elf_dir(list_file, dest_dir):
	f1 = open(list_file, "r");
	lines = f1.readlines();
	f1.close();
	os.system("mkdir -p " + dest_dir);
	for line in lines:
		copy_file(line, dest_dir);
	print("== TOTAL SIZE in kb ===");
	os.system("du -ks " + dest_dir);
	print("== TOTAL NUMBER (actual+1) ===");
	os.system("ls -l " + dest_dir + " | wc -l");

def extract_fname(line):
	idx = line.rindex("/");
	if idx==-1:
		return line;
	else:
		return line[idx+1:];

def copy_file(line, dest_dir):
	line = line.strip();
	fname = extract_fname(line);
	dest_path = dest_dir + "/" + fname;
	cmd1 = "cp " + line + "  " + dest_path;
	print(cmd1);
	os.system(cmd1);

# MAIN --------------
LIST_FILE= "list.txt";
DEST_DIR= "/tmp/elfs";
create_elf_dir(LIST_FILE, DEST_DIR);


