/** 
	Copyright Dr. CorrAuthor

	Author: Author1 
	All Rights Reserved.
	Created: 07/26/2022
*/
/* ALL extra tools functions for jsnark_driver package */
extern crate ark_ec;
extern crate ark_ff;
extern crate num_bigint;

use self::num_bigint::BigUint;
//use self::num_traits::{Zero, One};

use std::path::Path;
//use std::path::PathBuf;
//use std::fs::read_dir;
use std::fs::File;
use std::io::{BufReader, BufRead};
//use std::io::Result;

//use tools::*;
//use profiler::config::*;

use r1cs::dis_r1cs::*;
use r1cs::serial_r1cs::*;

use self::ark_ec::{PairingEngine};
use self::ark_ff::{/*Field,*/PrimeField,FftField/*,Zero,biginteger::BigInteger*/};

// 1. str_to_bi()
pub fn str_to_bi(num_str: &str) -> BigUint {
	// need to pass the number not the bytes
	let bytes = num_str.as_bytes();
	//return BigUint::from_bytes_le(bytes);
	return BigUint::parse_bytes(bytes,10).unwrap();
}
// 2. bi_to_fe<PrimeField>(bi: &BigInt) -> F { // fe = field element
pub fn bi_to_fr<PE:PairingEngine>(bi: &BigUint) -> PE::Fr { // takes PE and returns field element based on PE
	let bytes = bi.to_bytes_le();
	let fr = PE::Fr::from_le_bytes_mod_order(&bytes);
	return fr;
}

pub fn str_to_fr<PE:PairingEngine>(num_str: &str) -> PE::Fr {
	let bi = str_to_bi(num_str);
	return bi_to_fr::<PE>(&bi);
}

// test parse with is_satisfied() from serial R1CS
/// parse filepath and return R1CS object with field item
// Parsing method derived from CorrAuthor's previous parser and converted to proper type
//pub fn parse_ser<PE:PairingEngine>(filepath: String) -> R1CS<PE::Fr>, Vec<PE::Fr>{
pub fn parse_ser<PE:PairingEngine>(filepath: &str) -> (R1CS<PE::Fr>, Vec<PE::Fr>) {
    
	// stage 1, headers
	let mut field_order = str_to_fr::<PE>("0");
	let mut num_io = 0usize;
	let mut num_aux = 0usize;
	let mut num_constraints = 0usize;
	let mut num_segs = 0usize;
	let mut seg_size: Vec<usize> = vec![];

	// stage 2, assignments
	let mut var_assigns: Vec<PE::Fr> = vec![];

	// stage 3, constraints
	let mut a : Vec<Vec<LinearTerm<PE::Fr>>> = Vec::new(); 
	let mut b : Vec<Vec<LinearTerm<PE::Fr>>> = Vec::new(); 
	let mut c : Vec<Vec<LinearTerm<PE::Fr>>> = Vec::new(); 

	// 1. read file
	println!("REMOVE LATER: open file: {}", filepath);
	let file = File::open(filepath).unwrap();
	let reader = BufReader::new(file);
	let mut stage = 1; // 1 for headers; 2 for var assigns; 3 for constraints
	
	for (_, line) in reader.lines().enumerate(){
		let line = line.unwrap();
		//println!("Line: {}",line);
		let arr = line.split(" ").collect::<Vec<&str>>();
		let word1 = arr[0];
		if stage == 1{
			if word1 == "field_order:"{ 
				field_order = str_to_fr::<PE>(arr[1]); // for unused end value
			}else if word1=="primary_input_size:"{
				num_io = arr[1].parse::<usize>().unwrap(); 
			}else if word1=="aux_input_size:"{
				num_aux = arr[1].parse::<usize>().unwrap();
			}else if word1=="num_constraints:"{
				// initialize constraints
				num_constraints= arr[1].parse::<usize>().unwrap();
				for _i in 0..num_constraints{
					a.push(vec![]);
					b.push(vec![]);
					c.push(vec![]);
				}
            }else if word1=="num_segments:"{
				num_segs = arr[1].parse::<usize>().unwrap();
			}else if word1=="seg_size:"{
				let size = arr[1].parse::<usize>().unwrap();
				seg_size.push(size);
			}else if word1=="assignments:"{
				if num_segs != seg_size.len(){
					panic!("Error parsing r1cs: num_segments != seg_size.len()");
				}
				stage = 2;
			}else{
				panic!("Unknown keyword: {}\n", word1);
			}
		}else if stage==2{
			if word1=="constraints:"{
				stage = 3;
			}else{
				let w2 = arr[1];
				let val = str_to_fr::<PE>(w2);
				var_assigns.push(val); 
			}
		}else if stage==3{
			let cid = arr[0].parse::<usize>().unwrap(); // constraint id
			let mid = arr[1]; // matrix id
            let mut vid = 0usize;
			if arr[2] == "-1" { 
				vid = 0
			}
			else{
				vid = arr[2].parse::<usize>().unwrap(); // variable id
			}
			let coef = str_to_fr::<PE>(arr[3]);
			let max; // current matrix (a, b, or c)
			if mid=="A"{max = &mut a;}
			else if mid=="B"{max= &mut b;}
			else if mid=="C"{max= &mut c;}
			else{panic!("ERROR unknown matrix ID: {}\n", mid);}
			let lt = LinearTerm::<PE::Fr>::new(vid,coef);
			max[cid].push(lt);
		}else{
			panic!("ERROR: shouldn't reach stage {} here in parsing.\n", stage);
		}
	
	} 
	var_assigns.push(field_order);
	return (R1CS::new(a, b, c, num_io+num_aux, num_constraints, num_io, num_segs, seg_size), var_assigns);
}

