/** 
	Copyright Dr. CorrAuthor

	Author: Author1 , Dr. CorrAuthor
	All Rights Reserved.
	Created: 11/08/2022
	Revised: 01/12/2023 -> add local parser
	Revised: 01/22/2023 -> add arithmetic parser
*/

extern crate ark_ec;
extern crate ark_ff;
extern crate mpi;
extern crate num_bigint;

use std::str::FromStr;
use r1cs::dis_r1cs::*;
use r1cs::serial_r1cs::*;
use std::io::{BufWriter,Write};
//use r1cs::serial_r1cs::*;
use jsnark_driver::new_jd_tools::*;
use tools::*;
use profiler::config::*;
//use profiler::*;
use self::ark_ec::{PairingEngine};
use self::ark_ff::{Zero,PrimeField};
use poly::dis_vec::*;
use std::io::{BufReader,BufRead};
use poly::common::*;
use std::fs::File;
use self::num_bigint::BigUint;
//use std::fs::read_to_end;
//use self::mpi::traits::*;

//use self::mpi::environment::*;


/** Assumption: ac_dir has the information of AC-DFA:
	poly_dir has the information of polynomial witness for each fragment
	of input. 
	total_len is the total length of the input 4-bit nibbles.
	max_final_states: the number of final states in ACC. (for 
		zk-range proof later)
	server_id: the id of the server who owns poly_dir
	Return: DisR1CS instance, DisVars assignment, and 2dVector of
		variable map
*/
pub fn gen_dis_r1cs<PE:PairingEngine>(_server_id: usize, _ac_dir: &str, poly_dir: &str, curve_type: &str, _netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), max_final_states: usize, fd_log: &mut File) -> (DisR1CS<PE::Fr>,DisVec<PE::Fr>, Vec<Vec<(usize,usize)>>){
	//1. set up data (transfer data over network first, from main node)
	let b_perf = true;
	let b_mem = true;
	let b_test = true;

	let np = RUN_CONFIG.n_proc;
	let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	timer.clear_start();
	let mut case_id = 11223344u64;
	let vec_rand = vec![case_id];
	case_id = broadcast_vecu64(0, &vec_rand)[0]; 
	timer.stop();
	if b_perf {flog_perf(LOG1, &format!("Transfer Poly Evidence: "), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("Transfer Poly Evidence: "), fd_log);}
	

	//2. parallel start jsnark (TODO LATER next week).
	let total_len = read_1st_line_as_u64(&format!("{}/arr_aligned.dat", poly_dir)); 
	timer.clear_start();
	assert!(total_len%(252/4)==0, "total_len: {} % (252/4) !=0", total_len);
	let chunk_252 = total_len/(252/4); 
	let jsnark_dir = get_absolute_path("../jsnark/JsnarkCircuitBuilder/");
	//chunks_252bit idx np poly_dir case_id curve_type
	if b_perf {flog(LOG2, &format!("DEBUG USE 8883: jsnark: chunk_252: {}, me: {}, np: {}, case: {}, poly_dir: {}, curve_type: {}, max_final_states: {}", chunk_252, me, np, case_id, poly_dir, curve_type, max_final_states), fd_log);}
	let res = run_in_dir("java", &vec![tos("-Xmx4096m"), tos("-cp"), 
			tos("bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar"),
			tos("za_interface.ZaRegexCircRunner"),
			tos("genr1cs"),
			format!("{}", chunk_252),
			format!("{}", me),
			format!("{}", np),
			poly_dir.to_string(),
			format!("{}", case_id),
			format!("{}",curve_type),
			format!("{}", max_final_states)
	], &jsnark_dir);
	if b_perf {log(LOG1, &format!("JSnark Details -----\n{}-------\n", res));}
	if !res.contains("genR1cs completed"){
		panic!("ERROR at node: {} at producing Jsnark: ----\n {}", me, res);
	}
	RUN_CONFIG.better_barrier("wait for r1cs generated");
	timer.stop();
	log(LOG1, &format!("Generate local R1CS: {} ms", timer.time_us/1000));
	if b_perf {flog_perf(LOG1, &format!("RunJsnark"), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("RunJsnark"), fd_log);}

	//3. each node generates its local R1CS
	let curve_name = if curve_type=="BLS12-381" {"Bls381"} else {curve_type};
	let fpath = &format!("{}/circuits/{}/{}/ModularTraceVerifier_{}_Poseidon.r1cs.{}", jsnark_dir, case_id, me, curve_name, curve_name);
	let fpath_conn = &format!("{}/circuits/{}/{}/conn_vars.txt", jsnark_dir, case_id, me);
	let (r1cs, vars) = parse_serial_r1cs::<PE>(fpath);
	let vec_conns = parse_connectors(fpath_conn);
	if b_perf {flog_perf(LOG1, &format!("ParseLocalR1CS Constraints: {}: ", r1cs.num_constraints), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("ParseLocalR1CS"), fd_log);}

	//4. build the distributed R1CS instance first
	let (mut d_r1cs, var_map, vec_conn_global)=DisR1CS::<PE::Fr>::
			from_serial_each_node(r1cs, vec_conns, fd_log);
	if b_perf {flog_perf(LOG1, &format!("Local->DisR1CS: {}: ", d_r1cs.num_constraints), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("Local->DisR1CS"), fd_log);}

	//NOTE: d_r1cs.num_vars EXCLUDES constant 1
	let d_vars = DisR1CS::<PE::Fr>::
		vars_from_serial_each_node(&vars, &var_map, d_r1cs.num_vars+1, fd_log);
	if b_perf {flog_perf(LOG1, &format!("Build DisVars of Len: {}: ", d_vars.len), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("Build DisVars"), fd_log);}
	if b_test{
		let bres = d_r1cs.is_satisfied(&d_vars);
		if me==0{
			assert!(bres, "d_r1cs is NOT satisfied!");
		}
		if b_perf {flog_perf(LOG1, &format!("Check DisR1CS SAT: "), &mut timer, fd_log);}
		if b_mem {flog_mem(LOG1, &format!("Check DisR1CS SAT: "), fd_log);}
	}	


	//5. inject connector constraints into d_r1cs (at all node >0)
	//e.g., matching hash_out of prevoius node to hash_in of cur node 
	let conn_instr = report_connectors(&vec_conn_global);
	let size = d_r1cs.a_share.len();
	assert!(d_r1cs.b_share.len()==size, "b_share.len!=a_share!");
	assert!(d_r1cs.c_share.len()==size, "c_share.len!=a_share!");
	if me>0{//insert constraints
		let pairs = conn_instr.len()/2;
		let mut idx_spot = size;
		for i in 0..pairs{
			let var1 = conn_instr[i*2];
			let var2 = conn_instr[i*2+1];
			idx_spot = find_empty_spot(&d_r1cs, idx_spot - 1);
			insert_eq_cons(&mut d_r1cs, idx_spot, var1, var2);
		}
	}
	return (d_r1cs, d_vars, var_map);
}

/// report an empty spot, search backward
fn find_empty_spot<F:PrimeField>(dr1cs: &DisR1CS<F>, idx_start: usize)->usize{
	let mut idx = idx_start;
	loop{
		if dr1cs.a_share[idx].len()==0 && dr1cs.b_share[idx].len()==0
			&& dr1cs.c_share[idx].len()==0 { return idx;}
		idx -= 1;
		if idx==0 {panic!("CAN'T find empty spot! idx_start: {}", idx_start);}
	}
}

/// insert an equalty constraint that var1==var2 at idx of the constraint
fn insert_eq_cons<F:PrimeField>(dr1cs: &mut DisR1CS<F>, idx: usize, var1: usize, var2: usize){
	let one = F::one();
	let zero = F::zero();
	let neg_one = zero - one;
	//1. insert A: var1*1 - var2*1
	let term1 = LinearTerm{index: var1, value: one};
	let term2 = LinearTerm{index: var2, value: neg_one};
	dr1cs.a_share[idx].push(term1);
	dr1cs.a_share[idx].push(term2);

	//2. isnert into B: 1*1
	let term3 = LinearTerm{index: 0, value: one};
	dr1cs.b_share[idx].push(term3);

	//3. C: 0. no term
}

/// all nodes report their connectors to the main node (0)
/// main node construct the REAL connector array for each node
/// each node just need to build a constraint for each pair 
/// RETURN pair check instructions (even size vector)
pub fn report_connectors(conn: &Vec<usize>)->Vec<usize>{
	//1. report
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let main = 0;

	let vec_conns = all_to_one_vec(me, main, conn);
	let unit_size = conn.len();

	//2. build the pairs for each node. For node 0 just put zeros there
	let mut vec_data = vec![0usize; unit_size * np];
	if me==main{
		for node in 1..np{
			assert!(vec_conns[node].len()==unit_size, 
				"vec_conn[node] len wrong!");
			let start_idx = unit_size * node;
			for i in 0..unit_size/2{
				let var1 = vec_conns[node][i*2];
				let var2 = vec_conns[node-1][i*2+1];
				vec_data[start_idx+i*2] = var1;
				vec_data[start_idx+i*2+1] = var2;
			}
		} 
	}

	//3. broadcast
	let sizes = vec![unit_size; np];
	let vres = one_to_all(main, &vec_data, 	&sizes, 0usize);
	return vres;
}

/** Assumption: ac_dir has the information of AC-DFA:
	serer_id: who owns poly_dir
	poly_dir has the information of polynomial witness for each fragment
	of input. 
	total_len is the total length of the input 4-bit nibbles.
	Generate the VAR values ONLY (no need for r1cs)
		return teh local vars as well for debugging purpose
*/
pub fn gen_var_vals<PE:PairingEngine>(server_id: usize, poly_dir: &str, curve_type: &str, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), max_final_states: usize, var_map: &Vec<Vec<(usize,usize)>>, num_vars: usize, fd_log: &mut File) -> DisVec<PE::Fr>{
	let b_perf = false;
	let b_mem = false;

	//1. set up data (transfer data over network first, from main node)
	let mut timer = Timer::new();
	timer.clear_start();
	transfer_dir_from_server(server_id, poly_dir, netarch);
	let mut case_id = 11223344u64;
	let vec_rand = vec![case_id];
	case_id = broadcast_vecu64(0, &vec_rand)[0]; 
	if b_perf {flog_perf(LOG1, &format!("  Transfer Poly Evidence"), &mut timer, fd_log);}
	

	//2. parallel start jsnark 
	let total_len = read_1st_line_as_u64(&format!("{}/arr_aligned.dat", poly_dir)); 
	timer.clear_start();
	assert!(total_len%(252/4)==0, "total_len: {} % (252/4) !=0", total_len);
	let chunk_252 = total_len/(252/4); 
	let np = RUN_CONFIG.n_proc;
	let me = RUN_CONFIG.my_rank;
	let jsnark_dir = get_absolute_path("../jsnark/JsnarkCircuitBuilder/");
	//chunks_252bit idx np poly_dir case_id curve_type
	//log(LOG1, &format!("DEBUG USE 8885: jsnark: chunk_252: {}, me: {}, np: {}, case: {}, poly_dir: {}, curve_type: {}, max_final_states: {}", chunk_252, me, np, case_id, poly_dir, curve_type, max_final_states));
	let res = run_in_dir("java", &vec![tos("-Xmx4096m"), tos("-cp"), 
			tos("bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar"),
			tos("za_interface.ZaRegexCircRunner"),
			tos("genvars"),
			format!("{}", chunk_252),
			format!("{}", me),
			format!("{}", np),
			poly_dir.to_string(),
			format!("{}", case_id),
			format!("{}",curve_type),
			format!("{}", max_final_states)
	], &jsnark_dir);
	RUN_CONFIG.better_barrier("wait for r1cs generated");
	if b_perf{
		flog(LOG1, &format!("==== JSNARK Details for GenVars ===\n{}\n", res), fd_log);
	}
	if !res.contains("GenVars Total:"){
		panic!("ERROR at node: {} at producing Jsnark Varvalues: ----\n {}", 
		me, res);
	}
	if b_perf {flog_perf(LOG1, &format!("  JSnark GenLocal Vars"), &mut timer, fd_log);}
	if b_mem{flog_mem(LOG1, &format!("  JSnark GenLocal Vars"), fd_log);}

	//3. collect local result
	let fpath_vars = &format!("{}/circuits/{}/{}/vars.txt", jsnark_dir, case_id, me);  
	let vars_local = parse_vars::<PE>(fpath_vars);
	if b_perf {flog_perf(LOG1, &format!("  ParseLocalVars"), &mut timer, fd_log);}
	if b_mem{flog_mem(LOG1, &format!("  ParseLocalVars"), fd_log);}


	//4. generate the global ones
	let dis_vars = DisR1CS::<PE::Fr>::vars_from_serial_each_node(&vars_local, var_map, num_vars, fd_log); 
	if b_perf {flog_perf(LOG1, &format!("  LocalVar->DisVar"), &mut timer, fd_log);}
	if b_mem{flog_mem(LOG1, &format!("  LocalVar->DisVar"), fd_log);}

	return dis_vars;

}

/// models an arithmetic circuit evaluator
pub struct CircEvaluator<PE:PairingEngine>{
	//total number of wires 
	pub num_wires: usize, 
	//total number of vars 
	pub num_vars: usize, 
	//number of i/o (including column 1)
	pub num_io: usize, 
	//number of nizk/witness wires
	pub num_witness: usize, 
	//list of actions
	pub vec_actions: Vec<Action::<PE>>,
	//mapping from var id to wire_id
	pub var_to_wire: Vec<usize>,	
	//min wire ids of input: WE ASSUME ALL INPUT IDS are CONSECUTIVE!
	//SAME applies to output and nizk input wires
	//so just keep track of min and max IDs of these wire categorie.
	pub min_input_id: usize,
	pub max_input_id: usize,
	pub min_output_id: usize,
	pub max_output_id: usize,
	pub min_nizk_id: usize,
	pub max_nizk_id: usize,
}

/// Circuit operation code, corresponding to use used in
/// Jsnark
#[derive(Debug,PartialEq)]
pub enum CircOpCode{
	ConstMul,	
	Add,	
	Mul,	
	OpAssert,	
	Split,	
	Pack,	
	Input,
	NizkInput,
	Output
}

impl FromStr for CircOpCode{
	type Err = String;
	fn from_str(input: &str) -> Result<CircOpCode,Self::Err>{
		if input.starts_with("const-mul"){
			return Ok(CircOpCode::ConstMul);
		}
		match input{
			"add" => Ok(CircOpCode::Add),
			"mul" => Ok(CircOpCode::Mul),
			"assert" => Ok(CircOpCode::OpAssert),
			"split" => Ok(CircOpCode::Split),
			"pack" => Ok(CircOpCode::Pack),
			"input" => Ok(CircOpCode::Input),
			"output" => Ok(CircOpCode::Output),
			"nizkinput" => Ok(CircOpCode::NizkInput),
			_ => Err(format!("Unknown word: {}", input)),
		}
	}
}

/// represents an evaluator action
pub struct Action<PE:PairingEngine>{
	pub op: CircOpCode,
	pub input: Vec<usize>,
	pub output: Vec<usize>,
	pub const_arg: PE::Fr,  //ONLY used for const-mul
}

/// some methods of Action
impl <PE:PairingEngine> Action <PE>{
	fn dump(&self, prefix: &str){
		println!("{}: Action: me: {}, op: {:?}, input: {:?}, output: {:?}, const_arg: {}", prefix, RUN_CONFIG.my_rank, self.op, self.input, self.output, self.const_arg);
	}

	fn to_str(&self) -> String{
		return format!("Action: me: {}, op: {:?}, input: {:?}, output: {:?}, const_arg: {}", RUN_CONFIG.my_rank, self.op, self.input, self.output, self.const_arg);
	}

	/// execute on the vector of result
	fn exec(&self, vec: &mut Vec<PE::Fr>){
		if self.op==CircOpCode::ConstMul{
			assert!(self.output.len()==1, "ConstMul output len != 1");
			assert!(self.input.len()==1, "ConstMul input len != 1");
			vec[self.output[0]] = vec[self.input[0]] * self.const_arg;	
		}else if self.op==CircOpCode::OpAssert{
			let mut left = PE::Fr::from(1u64);
			for x in &self.input{
				left = left * vec[*x];
			}
			//assert!(left==vec[self.output[0]], "FAILED Assert Action: {}",
			//	&self.to_str());
		}else if self.op==CircOpCode::Add{
			assert!(self.output.len()==1, "Add output len != 1");
			assert!(self.input.len()>=1, "Add input len < 1");
			let mut left = PE::Fr::from(0u64);
			for x in &self.input{
				left = left + vec[*x];
			}
			vec[self.output[0]] = left;
		}else if self.op==CircOpCode::Mul{
			assert!(self.output.len()==1, "Mul output len != 1");
			assert!(self.input.len()>=1, "Mul input len < 1");
			let mut left = PE::Fr::from(1u64);
			for x in &self.input{
				left = left * vec[*x];
			}
			vec[self.output[0]] = left;
		}else if self.op==CircOpCode::Split{
			assert!(self.input.len()==1, "Split.input len != 1");
			assert!(self.output.len()>=1, "Split output len < 1");
			let fe = vec[self.input[0]];
			let s_num = if fe.is_zero() {"0".to_string()} else {format!("{}",fe)};
			let mut num = str_to_bi(&s_num); 
			let bits = self.output.len();
			let bi_one = BigUint::from(1u64);
			//let bi_zero = BigUint::from(0u64);

			for i in 0..bits{
				let res_one = &num & &bi_one;
				vec[self.output[i]] = if res_one.is_zero() {PE::Fr::zero()} else {PE::Fr::from(1u64)};
				num = num >> 1;
			} 
		}else if self.op==CircOpCode::Pack{
			assert!(self.input.len()>=1, "Pack.input len < 1");
			assert!(self.output.len()==1, "Pack.output len != 1");
			let two = PE::Fr::from(2u64);
			let mut factor = PE::Fr::from(1u64);
			let mut res = PE::Fr::from(0u64);
			for x in &self.input{
				let item = vec[*x];
				res = res + item * factor;
				factor = factor * two; 
			}
			vec[self.output[0]] = res;
		}else{
			self.dump("ACTION not handled yet:");
			panic!("ERROR: stop here");
		}
	}

	//processing strings to idx numbers	
	fn get_idx_arr(arr: &[&str])->Vec<usize>{
		let mut res = vec![0usize; arr.len()];
		for i in 0..arr.len(){
			let mut s = arr[i].clone();
			if s.starts_with("<"){
				s = &s[1..s.len()];
			}
			if s.ends_with(">"){
				s = &s[0..s.len()-1];
			}
			let idx = s.parse::<usize>().unwrap();
			res[i] = idx;
		}
		return res;
	}

	fn parse_from(arr: Vec<&str>)->Action<PE>{
		let op = CircOpCode::from_str(arr[0]).unwrap();
		//1. extract input
		assert!(arr[1]=="in", "arr[1]: {} is not 'in'!", arr[1]);
		let num_in = arr[2].parse::<usize>().unwrap();
		let arr_input = Self::get_idx_arr(&arr[3..3+num_in]);

		//2. extract output
		assert!(arr[3+num_in]=="out", "arr[3+num_in]: {} isnot 'out'", 
			arr[3+num_in]);
		let num_out = arr[4+num_in].parse::<usize>().unwrap();
		let arr_output= Self::get_idx_arr(&arr[5+num_in..5+num_in+num_out]);

		//3. extract argument
		let mut arg = PE::Fr::zero();
		if arr[0].contains("const"){
			let arr_words = arr[0].split("-").collect::<Vec<&str>>();
			let last_word = arr_words[arr_words.len()-1];
			arg = hex_str_to_fr::<PE>(last_word);
			if arr[0].contains("neg"){
				let zero = PE::Fr::zero();
				arg = zero - arg;
			}
		}
		let res = Action{op: op, input: arr_input, output: arr_output, const_arg: arg};
		return res;
	}

}



impl <PE:PairingEngine> CircEvaluator <PE>{
	pub fn parse_from(work_dir: &str, curve_name: &str)-> CircEvaluator<PE>{
		//let me = RUN_CONFIG.my_rank;
		let b_perf = true;
		let mut timer = Timer::new();
		timer.start();

		let fpath = &format!("{}/ModularTraceVerifier_{}_Poseidon.arith.{}", work_dir, curve_name, curve_name);
		let mut num_wires= 0;
		let mut num_io = 0;
		let mut num_witness = 0;
		let mut vec_action = vec![];
	
		//1. aprase the arithmetic file	
		let file = File::open(fpath).unwrap();
		let reader = BufReader::new(file);
		let mut min_input_id = num_wires+1;
		let mut max_input_id = 0;
		let mut min_output_id = num_wires+1;
		let mut max_output_id = 0;
		let mut min_nizk_id = num_wires+1;
		let mut max_nizk_id = 0;
		let mut num_input = 0;
		let mut num_output = 0;
		let mut num_nizk= 0;

		for (_, line) in reader.lines().enumerate(){
			let line = line.unwrap();
			let arr = line.split(" ").collect::<Vec<&str>>();
			let keyword = arr[0];
			if keyword=="total"{
				num_wires = arr[1].parse::<usize>().unwrap();
				min_input_id = num_wires+1;
				min_output_id = num_wires+1;
				min_nizk_id = num_wires+1;
			}else if keyword=="num_segments" ||
				keyword=="segment_size"{//do nothing
			}else if keyword=="input"{
				num_io += 1;	
				num_input += 1;
				let wire_id = arr[1].trim().parse::<usize>().unwrap();
				min_input_id = if min_input_id>wire_id {wire_id} else {min_input_id};
				max_input_id = if max_input_id>wire_id {max_input_id} else {wire_id}
			}else if keyword=="output"{
				num_io += 1;	
				let wire_id = arr[1].trim().parse::<usize>().unwrap();
				num_output += 1;
				min_output_id = if min_output_id>wire_id {wire_id} else {min_output_id};
				max_output_id = if max_output_id>wire_id {max_output_id} else {wire_id}
			}else if keyword=="nizkinput"{
				num_witness += 1;	
				let wire_id = arr[1].trim().parse::<usize>().unwrap();
				num_nizk += 1;
				min_nizk_id = if min_nizk_id>wire_id {wire_id} else {min_nizk_id};
				max_nizk_id = if max_nizk_id>wire_id {max_nizk_id} else {wire_id}
			}else if keyword.len()==0{//skip
			}else{
				let act = Action::parse_from(arr);
				vec_action.push(act);
			}
		}

		assert!(num_input==1, "ZaModular circ has 1 INPUT only!");
		assert!(max_input_id-min_input_id==num_input-1, "input lines are NOT consecutive!");
		assert!(max_output_id-min_output_id==num_output-1 || max_output_id==0, "output lines are NOT consecutive!");
		assert!(max_nizk_id-min_nizk_id==num_nizk-1 || max_nizk_id==0, "nizk lines are NOT consecutive!");
		if b_perf {log_perf(LOG1, " -- parse arith file", &mut timer);}


		//3. get the r1cs var size read the r1cs file 
		let fr1cs= &format!("{}/ModularTraceVerifier_{}_Poseidon.r1cs.{}", work_dir, curve_name, curve_name);
		let file = File::open(fr1cs).unwrap();
		let reader = BufReader::new(file);
		let mut num_vars = 0;
		let mut num_primary = 0;
		let mut num_aux = 0;
		for (_, line) in reader.lines().enumerate(){
			let line = line.unwrap();
			let arr = line.split(" ").collect::<Vec<&str>>();
			let keyword = arr[0];
			if keyword=="primary_input_size:"{
				num_primary = arr[1].parse::<usize>().unwrap();
			}else if keyword =="aux_input_size:"{
				num_aux= arr[1].parse::<usize>().unwrap();
			}
			if num_primary>0 && num_aux>0{
				num_vars = num_primary + num_aux;
				break;
			}
		}

		//4. get the variable mapping
		let fpath_map = &format!("{}/ModularTraceVerifier_{}_Poseidon.in.{}.varmap", work_dir, curve_name, curve_name);
		let file = File::open(fpath_map).unwrap();
		let reader = BufReader::new(file);
		let mut var_to_wire = vec![num_wires+100; num_vars]; //set invalid map
		let mut wire_id = 0;
		let mut var_id;
		let mut idx = 0;
		for (_, line) in reader.lines().enumerate(){
			let line = line.unwrap();
			let num = str_to_u64(&line) as usize;
			if idx%2==0{
				wire_id = num;
			}else{
				var_id = num;
				var_to_wire[var_id] = wire_id;
			}
			idx += 1;
		}
		if b_perf {log_perf(LOG1, " -- parse varmap", &mut timer);}


		//4. return
		let eval = CircEvaluator::<PE>{
			num_wires: num_wires, 
			num_vars: num_vars, 
			num_io: num_io,
			num_witness: num_witness,
			vec_actions: vec_action,
			var_to_wire: var_to_wire,
			min_input_id: min_input_id,
			max_input_id: max_input_id,
			min_output_id: min_output_id,
			max_output_id: max_output_id,
			min_nizk_id: min_nizk_id,
			max_nizk_id: max_nizk_id,
		};
		return eval;
	}

	/// generate the local variables
	pub fn gen_local_vars(&self, arrwit: &Vec<PE::Fr>)->Vec<PE::Fr>{
		let mut vres = vec![PE::Fr::zero(); self.num_wires]; 
		vres[0] = PE::Fr::from(1u64); //const column
		//1. copy over the witness
		let num_nizk = self.max_nizk_id - self.min_nizk_id + 1;
		for i in 0..num_nizk{
			let witid = self.min_nizk_id + i;
			vres[witid] = arrwit[i]; 
		} 
		vres[0] = PE::Fr::from(1u64); //other public OUTPUT will be set in exec


		//2. execute each action
		for act in &self.vec_actions{
			act.exec(&mut vres);
		}

		let mut var_res = vec![PE::Fr::zero(); self.num_vars];
		assert!(self.var_to_wire.len()==self.num_vars, "var_to_wire.len(): {} != num_vars: {}", self.var_to_wire.len(), self.num_vars);
		for var_id in 0..self.num_vars{
			let wire_id = self.var_to_wire[var_id];
			assert!(wire_id<self.num_wires, "INVALID map: wire: {} -> var: {}",
				wire_id, var_id);
			var_res[var_id] = vres[wire_id];
		}

		return var_res;
	}
}

// dump vars
pub fn dump_vars<F:PrimeField>(vec: &Vec<F>, fname: &String){
	let file = match File::create(fname){
		Ok(file) => file,
		Err(_) => panic!("Unable to open: {}", fname)
	};
	let mut buf = BufWriter::new(file);
	let num = vec.len();
	write!(&mut buf, "assignments: {}\n", &num).unwrap();
	let mut idx = 0;
	for x in vec{
		if x.is_zero(){
			write!(&mut buf, "{} 0\n", idx).unwrap();
		}else{
			write!(&mut buf, "{} {}\n", idx, &x).unwrap();
		}
		idx += 1;
	}
	buf.flush().unwrap();
}


