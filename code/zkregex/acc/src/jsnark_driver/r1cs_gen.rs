/** 
	Copyright Dr. CorrAuthor

	Author: Author1 
	All Rights Reserved.
	Created: 07/26/2022
*/

extern crate ark_ec;
extern crate flate2;
extern crate tar;
extern crate mpi;

use r1cs::dis_r1cs::*;
use r1cs::serial_r1cs::*;
use jsnark_driver::jd_tools::*;
use tools::*;
use profiler::config::*;
use self::ark_ec::{PairingEngine};
use poly::dis_vec::*;
use std::fs::File;
//use std::fs::read_to_end;
use self::flate2::Compression;
use self::flate2::Decompress;
use self::flate2::write::{GzEncoder};
use self::flate2::read::{GzDecoder};
use self::tar::Archive;
use self::mpi::traits::*;

//use self::mpi::environment::*;


/** Assumption: ac_dir has the information of AC-DFA:
	the following files are in it:
	???
	poly_dir has the information of polynomial witness for each fragment
	of input. 
	** assume poly_dir has the following structure **
	node1/ .... node_k/
	which each contains the data for each fragment.
	Constructs a Distributed R1CS object
*/
pub fn gen_dis_r1cs<PE:PairingEngine>(_ac_dir: &str, poly_dir: &str, _curve_type: &str) -> (DisR1CS<PE::Fr>,DisVec<PE::Fr>){
	//1. set up data (transfer data over network first, from main node)
	//transfer_dir_from_server(0, poly_dir);

	//2. parallel start jsnark (TODO LATER next week).
	unimplemented!("gen_dis_r1cs not fully implemented");
}

/** tar the dir as a file, read the file contents and return
a vector of bytes (call tools.read_vecu8() function for file reading)
*/
pub fn serialize_dir(_dir: &str, node:&usize) -> Vec<u8>{

	// 1. tar dir
	log(LOG1, &format!("Serializing: {}", _dir));
	let me = RUN_CONFIG.my_rank;
	let tar_name = format!("node_{}.tar.gz", &node);
	let tar_gz = File::create(&tar_name);
	//let tar_gzOp = File::create(&tar_name);
	if tar_gz.is_ok() {
		let enc = GzEncoder::new(tar_gz.unwrap(), Compression::default());
		let mut tar = tar::Builder::new(enc);
		/*let mut header = Header::new_gnu();*/
		tar.append_dir_all("./", _dir).unwrap();
		tar.finish();
		// 2. read contents with tools.read_vecu8() and return
		/*use std::io::{Seek as _, SeekFrom};
		test_file.seek(SeekFrom::Start(0)).expect("Failed to seek");
		*/
		let ser = read_vecu8(&tar_name);
		println!("Serial Size: {}", ser.len());
		return ser;
	}
	else{
		log(LOG1, &format!("FAILED TO SERIALIZE: {} to {}", &_dir, &tar_name));
		return Vec::new();
	}
}

/** unpack the data to the given dir*/
pub fn deserialize_dir(_dir:&str, _data: &Vec<u8>) /*-> Result<(), std::io::Error>*/ {
//pub fn deserialize_dir(_dir:&str, _data: &Vec<u8>){
	log(LOG1, &format!("Deserializing to : {}", _dir));
	//let new_tarf = &format!("{}_archive.tar.gz",_dir);
	//write_vecu8(_data, new_tarf);
	//let bytes: &[u8] = &_data;
	//let tar = GzDecoder::new(bytes);
	//let tar_gz = File::open(new_tarf).unwrap();
	let tar_gz = File::open(&format!("node_0.tar.gz")).unwrap();
	let tar = GzDecoder::new(tar_gz);
	let mut archive = Archive::new(tar);
	match archive.unpack(&_dir){
		Ok(status) => println!("{:?}", status),
		Err(error) => panic!("Problem deserializing data to {}: {:?}", _dir, error),
	};
	//write_vecu8(&s, &_dir.to_string());
}

/** pack each node_i folder as node_i.tar and transfer the file
	from main_node to node_i
	poly_dir has the polynomial evidence for fragment i
*/
pub fn transfer_files_from_main_node_outdated(poly_dir: &str){
	if 1>0 panic!("DO NOT CALL transfer_file_from_main_node. call tools/transfer_dir_from_server");
	log(LOG1, &format!("Transfer files: {} ", poly_dir));
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let world = RUN_CONFIG.univ.world();
	if me==0{//main node
		
		for _i in 0..np{
			let node_name = &format!("node_{}", _i);
			let new_dir = &format!("{}/witness/{}", poly_dir, node_name);
			let bytes:Vec<u8> = serialize_dir(new_dir, &_i);
			println!("Bytes size: {}",bytes.len());
			deserialize_dir(node_name, &bytes);
			//world.process_at_rank(_i as i32).send_with_tag(&bytes, me as i32);

			//1. serialize_dir for node i
			//log(LOG1, &format!("Transfer files i: {} ", &_i));
			//serialize_dir(poly_dir);
			//2. send the bytes to node_i (see dis_vec for send)
		}
	}else{
		//1. wait for a package from node 0
		//2. extract the bytes to the destination 
	}
	RUN_CONFIG.better_barrier("transfer_files");
}
