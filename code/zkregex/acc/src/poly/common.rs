/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 06/05/2022
	Reviesed: 03/07/2023 -> Added subvec related functions
	Common Utility Functions for Poly package
*/
extern crate ark_ff;
extern crate ark_poly;
extern crate ark_std;
extern crate mpi;
extern crate ark_serialize;

use crate::tools::*;
//use ark_ff::{FftField};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_poly::{univariate::DensePolynomial};
use self::ark_ff::PrimeField;
//use self::mpi::point_to_point::Status;
//use self::mpi::request::*;
use self::mpi::traits::*;
use self::mpi::environment::*;
use self::ark_std::log2;
use profiler::config::*;

const COUNT: usize = 256;
/** return the i'th share of start and end. Static version
	return (start, end) in the entire logical sequence.
	end index is ACTUALLY not included.
	In another word: len_partition = end-start
*/
pub fn get_share_start_end(i: u64, n: u64, total_len: u64) -> (usize, usize){
	let share_size = total_len/n;
	let start = (share_size*i) as usize;
	let end = if i==n-1 {total_len as usize} else {start+share_size as usize};
	return (start as usize, end as usize);
}

/// get the intersection: [start, end), end is actually not included.
pub fn share_intersect(sh1: &(usize, usize), sh2: &(usize, usize))->(usize, usize){
	let start = if sh1.0>sh2.0 {sh1.0} else {sh2.0};
	let mut end = if sh1.1<sh2.1 {sh1.1} else {sh2.1};
	if end<start {end = start;}
	return (start, end);
}

/** calculate the size for re_partition from node src to node j.
return a vector of 4 numbers
[start_off, end_off, start, end]
the start_off and end_off are the relative OFFSET of the data
INSIDE the partition of src node, the (start,end) are
the corresponding ABSOLUTE location in the entire distributed
vector. The END is actulaly NOT included. i.e.
len = end- start;
If NO DATA to send, set all to 0  */
pub fn gen_rescale_plan(src: usize, dst: usize, np: usize, cur_len: usize, target_len: usize) ->(usize, usize, usize, usize){
	let (src_start, src_end) = get_share_start_end(src as u64, np as u64, cur_len as u64);
	let (dest_start, dest_end) = get_share_start_end(dst as u64, np as u64, target_len as u64);
	let start = if src_start<dest_start {dest_start} else {src_start};
	let end = if src_end<dest_end {src_end} else {dest_end};
	//println!("DEBUG USE 889 --- gen_repart_plan: src: {}, dest: {}, target_len{}. src_start: {}, src_end{}, dest_start: {}, dest_end: {} => start: {}, end: {}", src, dst, target_len, src_start, src_end, dest_start, dest_end, start, end);
	if end>start{
		let start_off = start-src_start;
		let end_off = end-src_start;
		return (start_off, end_off, start, end);
	}else{
		return (0,0,0,0); //nothing to send
	}
}  

/** synchronous receive, receive a vector of vector of data. return size
is np */
pub fn receive_data<F:CanonicalSerialize+CanonicalDeserialize+Clone>(np: u64, univ: &Universe, vdata: &mut Vec<Vec<F>>, sample: F){
	return receive_data_worker1(np, univ, vdata, sample);
}

/** original version. mix the deseiralization and receive */
pub fn receive_data_worker1<F:CanonicalSerialize+CanonicalDeserialize+Clone>(np: u64, univ: &Universe, vdata: &mut Vec<Vec<F>>, sample: F){
	let world = univ.world();
	let b_perf = false;
	let mut timer= Timer::new();
	timer.start();
	for pid in 0..np{
		let r1 = world.process_at_rank(pid as i32).receive_vec::<u8>();
		if b_perf {log_perf(LOG1, "---- wait_for_receive", &mut timer);}
		let sample_clone = sample.clone();
		let data = from_vecu8::<F>(&r1.0, sample_clone);
		let proc = r1.1.source_rank();
		vdata[proc as usize] = data;
		if b_perf {log_perf(LOG1, "---- deseiralize", &mut timer);}
	}
}
/** 2nd version. separate the deseiralization and receive, will cost 1 more time of memory */
pub fn receive_data_worker2<F:CanonicalSerialize+CanonicalDeserialize+Clone>(np: u64, univ: &Universe, vdata: &mut Vec<Vec<F>>, sample: F){
	let world = univ.world();
	let b_perf = false;
	let mut timer= Timer::new();
	timer.start();
	let mut mydata = vec![vec![];  np as usize];
	for i in 0..np{
		let r1 = world.process_at_rank(i as i32).receive_vec::<u8>();
		let proc = r1.1.source_rank();
		mydata[proc as usize] = r1.0;
		if b_perf {log_perf(LOG1, "---- wait_for_receive", &mut timer);}
	}
	for pid in 0..np as usize{
		vdata[pid] = from_vecu8::<F>(&mydata[pid], sample.clone());
		if b_perf {log_perf(LOG1, "---- deseiralize", &mut timer);}
	}
}

pub fn async_receive_data<F:CanonicalSerialize+CanonicalDeserialize+Clone>(np_in: u64, univ: &Universe, vdata: &mut Vec<Vec<F>>, sample: F, rowsize: usize){
	let np = np_in as usize;
	let world = univ.world();
	let mut buf:Vec<Vec<u8>> = vec![vec![0u8;rowsize]; np];
	let mut timer = Timer::new();
	let mut t2= Timer::new();
	t2.start();
	mpi::request::multiple_scope(np, |scope,coll|{
		timer.start();
		let mut idx = 0;
		for row in buf.iter_mut(){
			let req = world.process_at_rank(idx as i32).
				immediate_receive_into(scope, row);
			coll.add(req);
			idx += 1;
		}
		//log_perf(LOG1, "REMOVE LATER 201: asynch_reqs", &mut timer);
		while coll.incomplete()>0{
			let (id,_,result) = coll.wait_any().unwrap();
			//log_perf(LOG1, "REMOVE LATER 202: wait_for_any", &mut timer);
			vdata[id]= from_vecu8(result, sample.clone());
			//log_perf(LOG1, "REMOVE LATER 203: convert_to_vecu8", &mut timer);
		}
	});
	//log_perf(LOG1, "REMOVE LATER 205: TOTAL", &mut t2);
}

/// All nodes send to ONE processor a u64 value
/// the main processor will return the VALID array 
/// element at 0 is for node 0 etc.
/// ALL other nodes get a Vec of 0u64.
/// size of Vec is number of processors
pub fn all_to_one(me: usize, main: usize, value: u64) -> Vec<u64>{
	let world = RUN_CONFIG.univ.world();
	let np = RUN_CONFIG.n_proc;
	let mut res = vec![0u64; np];
	res[me] = value;


	if me!=main{//send
		let vbytes = to_vecu8(&vec![value]);
		world.process_at_rank(main as i32).send_with_tag(&vbytes, me as i32);
	}else{
		for _i in 0..np-1{
			let r1 = world.any_process().receive_vec::<u8>();
			let vec = from_vecu8::<u64>(&r1.0, 0u64);
			if vec.len()==0{
				panic!("ERR all_to_1: RECEIVER: {} <-- {}. 0 element!, raw_data len: {}", me, r1.1.tag(), &r1.0.len());
			}
			let v = vec[0];
			let id = r1.1.tag() as usize;
			res[id] = v;
		}	
	}
	
	RUN_CONFIG.better_barrier("all_to_one");
	return res;
}

/** essentially the scatter_v function. sizes decides how many of the
elements from the data vector to be sent to each node.
ONLY the sender has the right data. BUT ALL ARE REQUIRED
TO HAVE THE same sizes. 
NOTE: cannot directly use rsmpi scater (coz its' index is limited to
2^31 (i32), which is too small for our application
*/
pub fn one_to_all<F:CanonicalSerialize+CanonicalDeserialize+Clone>(sender: usize, data: &Vec<F>, sizes: &Vec<usize>, sample: F)->Vec<F>{
	//1. build the parttions
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;

	//1. prepare data
	let mut vec_ret:Vec<F> = vec![];
	let mut vec_msg :Vec<Vec<u8>> = vec![vec![]; np as usize];
	if me==sender{
		let mut start_pos = 0;
		for i in 0..np{
			vec_msg[i]=slice_to_vecu8(&data[start_pos..start_pos + sizes[i]]);
			start_pos += sizes[i];
		}
		assert!(start_pos==data.len(),"final start_pos:{}!=data.len():{}", start_pos, data.len());
	}

	//2. send and receive
	mpi::request::scope(|scope|{
		let world = &RUN_CONFIG.univ.world();
		let mut requests = Vec::new();

		//1. MAIN node: build up the start_pos and range
		if me==sender{
			//let mut start_pos = 0;
			for i in 0..np{
				if i!=sender{
					requests.push(
						world.process_at_rank(i as i32).
							immediate_send(scope, &vec_msg[i])
					);
				}else{
					vec_ret = from_vecu8::<F>(&vec_msg[i], sample.clone());
				}
			}
		}else{
			let r1 = world.process_at_rank(sender as i32).receive_vec::<u8>();
			vec_ret = from_vecu8::<F>(&r1.0, sample);
		}

		if me==sender{
		 while let Some((_index, _status)) = 
			mpi::request::wait_any(&mut requests) {
            //    println!("DEBUG USE 108: Request index {} completed", index);
            }
		}
	});
	return vec_ret;
}

/// all sends to one main node a vector of values
/// ONLY the main node receives the CORRECT value!
pub fn all_to_one_vec<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(me: usize, main: usize, vec: &Vec<F>) -> Vec<Vec<F>>{
	let b_perf = false;
	let mut timer = Timer::new();
	timer.start();
	let world = RUN_CONFIG.univ.world();
	let np = RUN_CONFIG.n_proc;
	let mut res = vec![vec![]; np];
	res[me] = vec.to_vec();
	let sample = vec[0];
	if me!=main{//send
		let vbytes = to_vecu8(&vec);
		world.process_at_rank(main as i32).send_with_tag(&vbytes, me as i32);
	}else{//main node is the receiver
		for _i in 0..np-1{
			let r1 = world.any_process().receive_vec::<u8>();
			let vec_recv = from_vecu8::<F>(&r1.0, sample); 
			if vec_recv.len()==0{
				panic!("ERR all_to_1: RECEIVER: {} <-- {}. 0 element!, raw_data len: {}", me, r1.1.tag(), &r1.0.len());
			}
			let id = r1.1.tag() as usize;
			res[id] = vec_recv;
		}	
	}
	if b_perf {log_perf(LOG1, &format!("---- -- all_to_one_vec send/recv"), &mut timer);	}
	RUN_CONFIG.better_barrier("all_to_one");
	if b_perf {log_perf(LOG1, &format!("---- -- all_to_one_vec synch"), &mut timer);}	
	return res;
}


/// sender notifies every one a fixed array of F
/// Assumption: ALL should pass the SAME size of very small array
pub fn broadcast_small_arr<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(arr: &Vec<F>, sender_id: usize) -> Vec<F>{
	let mut timer = Timer::new();
	timer.start();
	let world = RUN_CONFIG.univ.world();
	let sender_proc = world.process_at_rank(sender_id as i32);
	let sample = arr[0];
	let mut vdata = to_vecu8(&arr); 
	sender_proc.broadcast_into(&mut vdata);
	RUN_CONFIG.better_barrier("wait for broadcast");
	let arr_res = from_vecu8(&vdata, sample);
	//log_perf(LOG1, "REMOVE LATER 201: broadcast_small_arr", &mut timer);
	return arr_res;
}

/// sender notifies every one a fixed array of F
/// Assumption: ALL should pass the SAME size of very small array
pub fn slow_broadcast_small_arr<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy+std::cmp::PartialEq>(arr: &Vec<F>, sender_id: usize) -> Vec<F>{
	let mut timer = Timer::new();
	let np = RUN_CONFIG.n_proc;
	let me = RUN_CONFIG.my_rank;
	timer.start();
	let world = RUN_CONFIG.univ.world();
	//let sender_proc = world.process_at_rank(sender_id as i32);
	//let sample = arr[0];
	let mut v = arr.clone();
	let vdata = to_vecu8(&arr); 
	if me==sender_id{
		for i in 0..np{
			if i!=me{
				world.process_at_rank(i as i32).
					send_with_tag(&vdata, me as i32);
			}
		}
	}else{
			let r1 = world.process_at_rank(sender_id as i32).
				receive_vec::<u8>();
			v = from_vecu8::<F>(&r1.0, arr[0]);
	}
	RUN_CONFIG.better_barrier("wait for broadcast");
	//log_perf(LOG1, "REMOVE LATER 201: broadcast_small_arr", &mut timer);
	return v;
}


/// All sends a small arr to receiver
/// Receiver builds a 2d array with each element corresponds
/// e.g. two nodes: node 0 and 1 send [1,2], [3,4] to node 0
/// node 0 will return [[1,2],[3,4]]
/// the the array received.
/// Assumption: ALL should pass the SAME size of very small array
/// receiver node gots a big 2d array, all others have EMPTY 2d array returned
pub fn gather_small_arr<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(arr: &Vec<F>, receiver_id: usize) -> Vec<Vec<F>>{
	let mut timer = Timer::new();
	timer.start();
	let world = RUN_CONFIG.univ.world();
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let root_proc = world.process_at_rank(receiver_id as i32);

	let vdata = to_vecu8(&arr);
	let unit_size = vdata.len();
	let mut toret = vec![vec![]; np];
	if me==receiver_id{
		let mut buf = vec![0u8; unit_size*np];
		root_proc.gather_into_root(&vdata[..], &mut buf[..]);
		let sample = arr[0];
		let arr_res = from_vecu8(&buf, sample);
		assert!(arr_res.len()%np==0, "arr_res.len: {} % np: {}!=0", arr_res.len(), np);
		let unit_size = arr_res.len()/np; 
		for i in 0..np{
			let slice = &arr_res[unit_size*i..unit_size*(i+1)];
			toret[i] = slice.to_vec();
		}
	}else{
		root_proc.gather_into(&vdata[..]);
	} 
	//log_perf(LOG1, "REMOVE LATER 202: gather_small_arr", &mut timer);
	return toret;
}

/** non-blocking broadcast to all peers. Each peer has a vector of F in
vec */
pub fn nonblock_broadcast_old<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	//log(LOG1, &format!("sending elements: {}", vec.len()*vec[0].len()));
	//1. convert 
	let b_perf = false;
	let b_mem = false;
	let mut timer = Timer::new();
	timer.start();
	let mut vec_msg :Vec<Vec<u8>> = vec![vec![]; np as usize];
	let mut idx = 0;
	for v in vec{
		vec_msg[idx] = to_vecu8(&v);
		idx+=1;
	}
	if b_perf {log_perf(LOG1, &format!("\n\n- build sendbuf: size: {}", vec[0].len()), &mut timer);}
	if b_mem {dump_mem_usage(" -- broadcast mem peak1 -- ");}

	//2. send all data ASYNCHRONOUSLY
	let mut vec_ret:Vec<Vec<F>> = vec![vec![]; np as usize];
	mpi::request::scope(|scope|{
		let world = &univ.world();
		let mut requests = Vec::new();
		//println!("DEBUG USE 107: start to asynch send cols:");
		for i in 0..np{
			//println!("DEBUG USE 107.1: {} --> {}", my_rank, i);
			let msg = &(vec_msg[i as usize]);
			requests.push(
				world.process_at_rank(i as i32).
				immediate_send(scope, msg)
			);
		}
		if b_perf {log_perf(LOG1, &format!("- imm sends"), &mut timer);}
		receive_data(np, univ, &mut vec_ret, sample);
		if b_perf {log_perf(LOG1, &format!("- receive data"), &mut timer);}
		 while let Some((_index, _status)) = 
			mpi::request::wait_any(&mut requests) {
            //    println!("DEBUG USE 108: Request with index {} completed", index);
            }
	//RECOVER LATER if not working.
	//	RUN_CONFIG.better_barrier("nonblock_broadcast");
		if b_perf {log_perf(LOG1, &format!("- wait for sends done"), &mut timer);}
		//println!("DEBUG USE 109: All requests completed");
	});
	if b_mem {dump_mem_usage(" -- broadcast mem peak2 -- ");}
	return vec_ret;
}

/** using all-to-all */
pub fn nonblock_broadcast_new_worker1<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	//1. check if it is ok to do all-to-all
	let b_perf = false;
	let mut t1= Timer::new();
	t1.start();
	let mut t2= Timer::new();
	t2.start();
 
	let unit_size = vec[0].len();
	for v in vec{
		if v.len()!=unit_size{
	//		println!("DEBUG USE 301: call non_blockbroadcast_old");
			return nonblock_broadcast_old(vec, np, univ, sample);
		}
	}

	//2. flatten the result
	let mut vec1d_send = vec![sample; unit_size * vec.len()];
	for i in 0..vec.len(){
		let (begin, end) = (i*unit_size, (i+1)*unit_size);
		vec1d_send[begin..end].copy_from_slice(&vec[i][0..]);
	}
	if b_perf {log_perf(LOG1, &format!("------ broadcast_wk1 Step1: copy_from_slice. TOTAL size: {}", vec1d_send.len()), &mut t1);}
	let vsend = to_vecu8(&vec1d_send);
	if b_perf {log_perf(LOG1, "------ broadcast_wk1 Step2: to_vec8", &mut t1);}
	let mut vrecv = vec![0u8; vsend.len()];

	//3. all_to_all
	let world = RUN_CONFIG.univ.world();
	world.all_to_all_into(&vsend[..], &mut vrecv[..]);
	if b_perf {log_perf(LOG1, "------ broadcast_wk1 Step3: all_to_all_into", &mut t1);}
	let vec1d_receive = from_vecu8(&vrecv, sample);
	if b_perf {log_perf(LOG1, "------ broadcast_wk1 Step4: from_u8", &mut t1);}
	//log_perf(LOG1, "REMOVE LATER 204: from_u8", &mut t1);

	//3. reconstruct the result
	let mut res = vec![vec![]; vec.len()];
	for i in 0..vec.len(){
		let (begin, end) = (i*unit_size, (i+1)*unit_size);
		res[i] = vec1d_receive[begin..end].to_vec();
	}
	if b_perf {log_perf(LOG1, "------ broadcast_wk1 Step5: assemble", &mut t1);}
	if b_perf {log_perf(LOG1, "------ broadcast_wk1 TOTAL", &mut t2);}
	//log_perf(LOG1, "REMOVE LATER 205: reconstruct", &mut t1);
	return res;
}

/** using all-to-all (asynch)*/
pub fn nonblock_broadcast_new_worker2<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	//1. check if it is ok to do all-to-all
	let unit_size = vec[0].len();
	for v in vec{
		if v.len()!=unit_size{
			//println!("DEBUG USE 301: call non_blockbroadcast_old");
			return nonblock_broadcast_old(vec, np, univ, sample);
		}
	}

	//2. flatten the result
	let mut t1 = Timer::new();
	t1.start();
	let mut vec1d_send = vec![sample; unit_size * vec.len()];
	for i in 0..vec.len(){
		let (begin, end) = (i*unit_size, (i+1)*unit_size);
		vec1d_send[begin..end].copy_from_slice(&vec[i][0..]);
	}
	//log_perf(LOG1, "REMOVE LATER 201: copy_from_slice", &mut t1);
	let vsend = to_vecu8(&vec1d_send);
	//log_perf(LOG1, "REMOVE LATER 202: to_vecu8", &mut t1);
	let mut vrecv = vec![0u8; vsend.len()];

	//3. all_to_all
	mpi::request::scope(|scope|{
		let world = RUN_CONFIG.univ.world();
		world.immediate_all_to_all_into(scope,&vsend[..], &mut vrecv[..]).wait();
	});
	//log_perf(LOG1, "REMOVE LATER 203: all_to_all", &mut t1);
	let vec1d_receive = from_vecu8(&vrecv, sample);
	//log_perf(LOG1, "REMOVE LATER 204: from_u8", &mut t1);

	//3. reconstruct the result
	let mut res = vec![vec![]; vec.len()];
	for i in 0..vec.len(){
		let (begin, end) = (i*unit_size, (i+1)*unit_size);
		res[i] = vec1d_receive[begin..end].to_vec();
	}
	//log_perf(LOG1, "REMOVE LATER 205: reconstruct", &mut t1);
	return res;
}

/** non-blocking broadcast to all peers. 
Try managed duplix worker mode and try to
read specific rank.
Assumption: all process SENDS the SAME AMOUNT OF DATA.
*/
pub fn nonblock_broadcast_new_worker3<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np_inp: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	//1. init 
	let me = RUN_CONFIG.my_rank;
	let np = np_inp as usize;
	let mut vec_ret:Vec<Vec<F>> = vec![vec![]; np];
	vec_ret[me] = vec[me].clone();
	let size0 = vec[0].len();
	let mut nxt_proc = (me+1)%np;
	for v in vec{ if v.len()!=size0 { panic!("v.size!=size0"); } }
	let world = &univ.world();
	let mut nxt_msg = to_vecu8(&vec[nxt_proc]);
	let mut msg = nxt_msg.clone();

	for i in 1..np{
		mpi::request::scope(|scope|{
			//2.2.1 asynch send and asynch receive
			msg.copy_from_slice(&nxt_msg); //strange borrow, a little waste
			let sreq = world.process_at_rank(nxt_proc as i32). 
				immediate_send(scope, &msg);

			//2.2.2 while sending: prep next buffer
			if i<np-1{//skip the last one
				nxt_proc = (me + i + 1) % np;
				nxt_msg = to_vecu8(&vec[nxt_proc]);
			}

			//2.2.3 get the arriving from prev_proc
			let prev_proc = (me+np-i) % np;
			let (buf,_) =  world.process_at_rank(prev_proc as i32).receive_vec::<u8>();

			vec_ret[prev_proc] = from_vecu8(&buf, sample);	

			//2.2.4 confirm sent done
			sreq.wait();
		});//end of mpi scope
	}
	RUN_CONFIG.better_barrier("nonblock_broadcast");
	return vec_ret;
}

pub fn nonblock_broadcast_new_worker4<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	//1. send all data ASYNCHRONOUSLY
	let mut vec_ret:Vec<Vec<F>> = vec![vec![]; np as usize];
	let size0 = vec[0][0].uncompressed_size() * vec[0].len();
	let mut vec_data = vec![vec![0u8; size0]; np as usize];
	mpi::request::scope(|scope|{
		let world = &univ.world();
		let mut requests = Vec::new();
		let mut idx = 0; 
		let mut timer = Timer::new();
		let mut t2= Timer::new();
		timer.start();
		t2.start();
		for row in vec_data.iter_mut(){
			to_vecu8_in_place(&vec[idx], row);
			requests.push(
				world.process_at_rank(idx as i32).
				immediate_send(scope, row)
			);
			idx+=1;
		}
		let row_size = size0;
		async_receive_data(np, univ, &mut vec_ret, sample, row_size);
		//receive_data(np, univ, &mut vec_ret, sample);
		 while let Some((_index, _status)) = 
			mpi::request::wait_any(&mut requests) {
            //    println!("DEBUG USE 108: Request with index {} completed", index);
            }
		RUN_CONFIG.better_barrier("nonblock_broadcast");
	});
	return vec_ret;
}

//do one round of ping pong
pub fn ping_pong(n: usize){
	//only do one round of send and receive between rankd and 0 and 1
	let mut timer = Timer::new();
	timer.start();
	let me = RUN_CONFIG.my_rank as usize;
	let world = RUN_CONFIG.univ.world();
	let vbytes = vec![10u8; 1024];
	for _i in 0..n{
		if me==0{
			world.process_at_rank(1).send_with_tag(&vbytes, me as i32);
			let _r1 = world.process_at_rank(1).receive_vec::<u8>();
		}else if me==1{
			let _r1 = world.process_at_rank(0).receive_vec::<u8>();
			world.process_at_rank(0).send_with_tag(&vbytes, me as i32);
		}
	}
	RUN_CONFIG.better_barrier("ping_poing");
	timer.stop();
	if me==0{
		println!("PING PONG Perf: tota: {} us, avg: {} us", timer.time_us, timer.time_us/n);
	}
	
}

/** non-blocking broadcast to all peers. Each peer has a vector of F in
vec */
pub fn nonblock_broadcast_new<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	let mut t1 = Timer::new();
	t1.start();
	let mut total_size = 0;
	let size_1strow = vec[0].len();
	//when row size not exactly equal, have to use old worker
	let mut have_to_use_old_worker = false;
	for i in 0..vec.len(){
		total_size += vec[i].len();
		if vec[i].len()!=size_1strow {have_to_use_old_worker=true;}
	}
	let switch_pt = RUN_CONFIG.log_broadcast_alg_switch;
	let bar = 1<<switch_pt; 
	let res;
	if total_size*(np as usize)<=bar && !have_to_use_old_worker{
		//log(LOG1, &format!("DEBUG USE 777: total_size: {}, bar: {}, have_to: {}. USE alg2!", total_size, switch_pt, have_to_use_old_worker));
		res = nonblock_broadcast_new_worker1(vec, np, univ, sample);
	}else{
		//log(LOG1, &format!("DEBUG USE 778: total_size: {}, bar: {}, have_to: {}. USE old_worker", total_size, switch_pt, have_to_use_old_worker));
		res = nonblock_broadcast_old(vec, np, univ, sample);
	}
	return res;
}


/** LEGACY version for some functions in DisPoly.
Somehow the nonblock_broadcast_new_worker does not work
*/
pub fn nonblock_broadcast<F: CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(vec: &Vec<Vec<F>>, np: u64, univ: &Universe, sample: F)->Vec<Vec<F>>{
	let res = nonblock_broadcast_old(vec, np, univ, sample);
	return res;
}

/// from ark_poly_commit/kzg10
pub fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField>(
    p: &DensePolynomial<F>,
) -> (usize, Vec<F>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs.len() && p.coeffs[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = &p.coeffs[num_leading_zeros..];
    (num_leading_zeros, coeffs.to_vec())
}

/// get the closet power of 2
pub fn closest_pow2(n: usize)->usize{
	let k = log2(n);
	let n2 = 1<<k;
	return n2;
}

/*
/// from ark_poly_commit/kzg10
pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    coeffs
}
*/

fn bigger(a: usize, b: usize) -> usize{
	return if a>b {a} else {b};
}

fn smaller(a: usize, b: usize) -> usize{
	return if a>b {b} else {a};
}

fn intersect(r1: (usize, usize), r2: (usize, usize))-> (usize,usize){
	let b1 = bigger(r1.0, r2.0);
	let b2 = smaller(r1.1, r2.1);
	return if b1<b2 {(b1, b2)} else {(0,0)};
}

/// assuming there is a DisVec or GroupDisVec of total_len
/// for generating a sublist of [start, end)
/// generate a transfer data plan
/// res[i][j] is a tuple (me_start, me_end, dest_start, dest_end)
/// (me_start, me_end) is the the PARITION range to copy from 
/// (dest_start, dest_end) is the PARITTION range to copy to (new)
/// both ends are not really included 
pub fn gen_subvec_plan(total_len: usize, np: usize, start: usize, end: usize) ->Vec<Vec<(usize, usize, usize, usize)>>{
	assert!(end>=start, "gen_subvec ERR: end<start");
	assert!(end<=total_len, "gen_subvec ERR: end>total_len");
	
	let mut res = vec![vec![(0,0,0,0); np]; np];
	let new_len = end-start;
	for src in 0..np{
		let src_start = total_len/np*src; 
		let src_end = if src<np-1 {total_len/np*(src+1)} else {total_len};
		//in sublist
		let new_src_start = if src_start<start {0} else {src_start-start};
		let new_src_end = if src_end<start {0} else {src_end-start}; 
		for dest in 0..np{
			let dest_start = new_len/np*dest;
			let dest_end= if dest<np-1 {new_len/np*(dest+1)} else {new_len};
			let (b1, b2) = intersect((new_src_start, new_src_end), (dest_start, dest_end)); //in new list
			if b2>b1{
				//log(LOG1, &format!("REMOVE LATER 101: total_len: {}, start: {}, end: {}, src: {}, src_start: {}, src_end: {}, new_src_start: {}, new_src_end: {}, dest: {}, dest_start: {}, dest_end: {}: b1: {}, b2: {}", total_len, start, end, src, src_start, src_end, new_src_start, new_src_end, dest, dest_start, dest_end, b1, b2));
				res[src][dest] =(b1+start-src_start, b2+start-src_start, b1-dest_start, b2-dest_start);
				//log(LOG1, &format!("REMOVE LATER 102: res[{}][{}]: {:?}", src, dest, res[src][dest]));
			}
		}
	}
	return res;
}

/// This can be called by DisVec and GroupDisVec for generate a sublist
pub fn subvec<F:CanonicalSerialize+CanonicalDeserialize+Clone+Copy>(mypartition: &Vec<F>, total_len: usize, me: usize, np: usize, start: usize, end: usize)->Vec<F>{
	//1. generate the partition plan
	let plan = gen_subvec_plan(total_len, np, start, end); 

	//2. prepare to send
	let mut vec_to_send = vec![vec![]; np]; 
	for dest in 0..np{
		let (me_start, me_end, _, _) = plan[me][dest];
		vec_to_send[dest] = mypartition[me_start..me_end].to_vec();	
	} 

	//3. broadcast
	let sample = mypartition[0].clone();
	let vrec = nonblock_broadcast(&vec_to_send, np as u64, &RUN_CONFIG.univ, sample);

	//4. assemble
	let mut total_size = 0;
	for i in 0..np {total_size += plan[i][me].3 - plan[i][me].2};
	let mut res = vec![sample; total_size];
	for i in 0..np{
		let src_data = &vrec[i];
		let (dest_start, dest_end) = (plan[i][me].2 , plan[i][me].3);
		assert!(src_data.len()==dest_end-dest_start, "src_data.len(): {} != dest_end - dest_start: {}", src_data.len(), dest_end-dest_start);
		for j in 0..dest_end-dest_start{
			res[dest_start+j] = src_data[j];
		}
	}

	//5. return
	return res;
}
