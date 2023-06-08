/* ***************************************************
Dr. CorrAuthor
@Copyright 2022
Created: 11/10/2022
* ***************************************************/

/** **************************************************
This is basically a replication of ZaModulvarVerifier.
Its random_sample() function is NOT implemented, 
thus cannot be used for unit testing.
So that we do not have dependence on main and nfa/ac packages.
* ***************************************************/
package za_interface.za.circs.zkreg;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import java.util.Arrays;
import java.util.ArrayList;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.PrimeFieldInfo;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.hash.poseidon.*;
import util.Util;

/** **************************************************
This is a verifier for a valid trace of running a string over an automaton.
As this is the i'th component of np (number of modules). Care should
be taken in handling length.
Assume:
	N: the input length of the entire input string
	np: the number of modules
	n: the size of the chunk of input for this i'th component. It is
required that this is distributed evenly:
		n = if i less than np-1 then {N/np} otherwise {N/np + N%np}
	NT: total number of transitions for entire sequence
		NT = 2*N + 1 (+1 for polynomial coef size 1 higher than the degree)
	nt: the chunk size of transitions would be 2*N/np
			or NT/np + NT%np for last chunk
	NS: number of states for entire sequence: 
		because state sequence have to be padded
		to allow CBC mode (the ending state is the same as
		the first state of next chank). 
		NS = 2*N + np + 1 (= 2*N + 2 + np - 1)
		Why? states has one more than the number of transitions.
	ns: the size of the states input for the i'th chunk
		ns = if i less than np-1 then {NS/np} otherwise {NS/np + NS%np}
-----------------------------------------------------
public input: r (random challenge) - when applying Fiat-Shamir it
		can be set the the hash of the commited segments 0 and 1.
Input: (all secret witness)
	*** segment 0 ****
	arrStates: array of states (size: n+1)
	arrInput: the sequence of input characters, including
		the padded chars
		as the result of fail edges and padding.  (size: 2n)
	arrBFail: whether the corresponding input (transition) should be 
		regarded as a fail edge in Aho-Corasic DFA. 
		If the flag is set to true, then
		the corresponding character should be IGNORED in building the hash.
		(size: nt)
	arrAlignedInput: the compacted input keeping the original order
but with the characters on Fail Edges removed (ALWAYS make sure that
we don't need to pad it). [size: n]
	---- Set support part ---- 
	---- (also check main/.../acc_driver/AccDriver for definitions) ---
	---- each array will have size ns for S_ series and nt for T_ series
	S_P: polynoail for states representing states
	S_GCD: GCD of S_P and S_PD (PD stands for derivative of P). Note: PD
		can be easily calculated from P.
	S_P_GCD: P/GCD
	S_PD_GCD: PD/GCD. 
	S_S: Bizout coefs for proviing S_P_GCD and S_PD_GCD are disjoint
	S_T: 2nd Bizout coefs
	T_P: the following are the poly version for the sets of transitions
	T_GCD
	T_P_GCD
	T_PD_GCD
	T_S 
	T_T
	// -- the following will not be included COMPARED with earlier version
	// NO NEED TO PROVE. It's implied by the speical digitizeTransition encoding
	// T_TS: Biztou coefs for showing set of states and transitions are disjoint 	// S_TS:

	*** Segment 1 ***
	z: the blinding factor for evaluating polynomials (see paper for
		prfblindval
	r1: blinding factor for segment 0
	r2: the blinding factor for building Pedersen commitment comm_z = g^z h^r2

	*** Segment 2 ***
	---- the following are packed in chunked_inputs.dat ------
	---- NOTE even if they are named out - they can be passed in as input
	--- the circuit will compute the value again and verify correctness
	--- the addition "out" wires are used to facilitate testing of 
	--- modular circuits (wasted about 15 wires, but the cost is negligible)
	p_acc_states_in: (r+s1)(r+s2) ... (r+sn)
	p_acc_transitions_in: (r+t1)* ... *(r+tn)
	hash_in: the input hash for chaining hash
	v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, vs_s, v_s_t_in,
	v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, vs_s_in, v_t_t_in,
	
	p_acc_states_out: (r+s1)(r+s2) ... (r+sn)
	p_acc_transitions_out: (r+t1)* ... *(r+tn)
	hash_out: the hash of all input characters in arrAlignedInput.
		Note: if the input is less than the circuit size, padd it with 0.
	v_s_p: v_s_p_in + S_P(r) * r^{i*ns} 
	v_s_pd, v_s_gcd, v_s_p_gcd, v_pd_gcd, v_s_s, v_s_t, 
	v_t_p, v_t_pd, v_t_gcd, v_t_v_gcd, v_t_pd_gcd,
	v_t_s, v_t_t, (defined likely wise, replace "ns" to "nt")
* ***************************************************/

public class ZaModularVerifierV3 extends ZaCirc{
	/* this module is the i'th modular circuit */
	protected int module_idx; 
	/* the total number of modular circuits */
	protected int num_modules; 


	/* max idx of final state. assuming all final states in range [0,max_final_state]*/
	protected int max_final_state_idx;
	/* the size of REAL input string for ALL modules */
	protected int N;
	/* TOTAL number of states entirely */
	protected int NS; 
	/* TOTAL Number of transitions entirely */
	protected int NT;
	/* the number of input chars in input string for THIS module */
	protected int n;  
	/* the number of states when the input chunk of THIS module is traversed*/
	protected int ns;
	/* the number of transitions */
	protected int nt;
	/** number of bits to encode a state */
	protected int state_bits;

	/** arr of states. size will be 2n + 1. might be padded with fail
		edges */
	protected Wire [] arrStates;
	/** arr of chars of input string, size will be 2n. might be padded
		with fail edges. */
	protected Wire [] arrInput;
	/** arr of boolean flags where (arrStates[i],arrInputs[i]) is a fail edge
		transition, size 2n */
	protected Wire [] arrBFail;
	/** compressed input by removing fail edges. Size n. Unless it's at
the end of an input file, this should be run at full capacity without padding.
When it's at the end of an input file, it can be padded with 0 at the end. */
	protected Wire [] arrAlignedInput;
	/** All following's length will be 2n+2. Poly for multi-sets of states */
	protected Wire [] S_P;	
	/** GCD of S_P and S_PD */
	protected Wire [] S_GCD;
	/** P - GCD. This is the set support (standard set) of states */
	protected Wire [] S_P_GCD;
	/**  Derivative of P - GCD */
	protected Wire [] S_PD_GCD;
	/* Bizout coef1 for proving S_P_GCD and S_PD_GCD are disjoint */
	protected Wire [] S_S;
	/* 2nd Bizout coef */
	protected Wire [] S_T;
	/** All following's length will be 2n+2. Poly for multi-sets of trans*/
	protected Wire [] T_P;	
	/** GCD of S_P and T_PD */
	protected Wire [] T_GCD;
	/** P - GCD. This is the set support (standard set) of trans */
	protected Wire [] T_P_GCD;
	/**  Derivative of P - GCD */
	protected Wire [] T_PD_GCD;
	/* Bizout coef1 for proving T_P_GCD and T_PD_GCD are disjoint */
	protected Wire [] T_S;
	/* 2nd Bizout coef */
	protected Wire [] T_T;

	/** modular input for p_acc_states*/
	protected Wire p_acc_states_in;
	/** modular input for p_acc_trans */
	protected Wire p_acc_transitions_in;
	/** hash_in */
	protected Wire hash_in;
	/** random nonce supplied by verifier, for evaluating polynomials */
	protected Wire r;
	/** inverse of r */
	protected Wire r_inv;
	/** the blinding factor for polynomial eval: z + p(r) */
	protected Wire z;
	/** the randon nonce for segment 0 */
	protected Wire r1;
	/** the randon nonce for commit_z = g^z h^r2*/
	protected Wire r2;
	/** output line: polynomial eval of acc for states */
	protected Wire p_acc_states_out;
	/** output line: polynomial eval of acc for transitions */
	protected Wire p_acc_transitions_out;
	/** output line: the hash of arrAlignedInput */
	protected Wire hash_out;
	/** evaluation of partial polynomial S_P(r) * r^{i*ns} */
	protected Wire v_s_p;
	/** evluation of partial polynomial PD(r) * r^{i*ns}. (derivative of P) */
	protected Wire v_s_pd;
	/** evaluation of S_GCD(r) * r^{i*ns} */
	protected Wire v_s_gcd;
	/** S_P_GCD(r) * r^{i*ns} This is ACTUALLY the set support
		of state set polynomial */
	protected Wire v_s_p_gcd;
	/** S_PD_GCD(r) * r^{i*ns} */
	protected Wire v_s_pd_gcd;
	/** S_S(r) * r^{i*ns} */
	protected Wire v_s_s;
	/** S_T(r) * r^{i*ns} */
	protected Wire v_s_t;

	/** evaluation of partial polynomial T_P(r) * r^{i*N} where N = 2n + 2 */
	protected Wire v_t_p;
	/** T_GCD(r) * r^{i*nt} This is ACTUALLY the set support
		of transition set polynomial */
	/** eval of partial poly derivative of P */
	protected Wire v_t_pd;
	/** eval of partial poly for GCD */
	protected Wire v_t_gcd;
	/** T_P_GCD(r) * r^{i*nt} */
	protected Wire v_t_p_gcd;
	/** PD_GCD(r) * r^{i*nt} */
	protected Wire v_t_pd_gcd;
	/** T_S(r) * r^{i*nt} */
	protected Wire v_t_s;
	/** T_T(r) * r^{i*nt} */
	protected Wire v_t_t;
	// the following are the corresponding input for the above
	protected Wire v_s_p_in;
	protected Wire v_s_pd_in;
	protected Wire v_s_gcd_in;
	protected Wire v_s_p_gcd_in;
	protected Wire v_s_pd_gcd_in;
	protected Wire v_s_s_in;
	protected Wire v_s_t_in;
	protected Wire v_t_p_in;
	protected Wire v_t_pd_in;
	protected Wire v_t_gcd_in;
	protected Wire v_t_p_gcd_in;
	protected Wire v_t_pd_gcd_in;
	protected Wire v_t_s_in;
	protected Wire v_t_t_in;
	
	// --- The following are for logical evaluation --
	/** for logical eval, corresponding to arrStates*/
	protected BigInteger[] arrStates_logical;
	/** for logical eval, corresponding to arrInput */
	protected BigInteger [] arrInput_logical;
	/** for logical evla, corresponding to arrBFail */
	protected BigInteger [] arrBFail_logical;
	/** for logical eval, corresponding to arrAlignedInput */
	protected BigInteger [] arrAlignedInput_logical;

	/** All following's length will be 2n+2. Poly for multi-sets of states */
	protected BigInteger [] S_P_logical;	
	/** GCD of S_P and S_PD */
	protected BigInteger [] S_GCD_logical;
	/** P - GCD. This is the set support (standard set) of states */
	protected BigInteger [] S_P_GCD_logical;
	/**  Derivative of P - GCD */
	protected BigInteger [] S_PD_GCD_logical;
	/* Bizout coef1 for proving S_P_GCD and S_PD_GCD are disjoint */
	protected BigInteger [] S_S_logical;
	/* 2nd Bizout coef */
	protected BigInteger [] S_T_logical;

	/** All following's length will be 2n+2. Poly for multi-sets of trans*/
	protected BigInteger [] T_P_logical;	
	/** GCD of S_P and T_PD */
	protected BigInteger [] T_GCD_logical;
	/** P - GCD. This is the set support (standard set) of trans */
	protected BigInteger [] T_P_GCD_logical;
	/**  Derivative of P - GCD */
	protected BigInteger [] T_PD_GCD_logical;
	/* Bizout coef1 for proving T_P_GCD and T_PD_GCD are disjoint */
	protected BigInteger [] T_S_logical;
	/* 2nd Bizout coef */
	protected BigInteger [] T_T_logical;

	/** modular input for p_acc_states*/
	protected BigInteger p_acc_states_in_logical;
	/** modular input for p_acc_trans */
	protected BigInteger p_acc_transitions_in_logical;
	/** hash_in */
	protected BigInteger hash_in_logical;
	/** random nonce supplied by verifier, for evaluating polynomials */
	protected BigInteger r_logical;
	protected BigInteger r_inv_logical;
	/** the blinding factor for polynomial eval: z + p(r) */
	protected BigInteger z_logical;
	/** blinding factor for witness segment 0 */
	protected BigInteger r1_logical;
	/** the randon nonce for commit_z = g^z h^r2*/
	protected BigInteger r2_logical;
	/** output line: polynomial eval of acc for states */
	protected BigInteger p_acc_states_out_logical;
	/** output line: polynomial eval of acc for transitions */
	protected BigInteger p_acc_transitions_out_logical;
	/** output line: the hash of arrAlignedInput */
	protected BigInteger hash_out_logical;
	/** evaluation of partial polynomial S_P(r) * r^{i*ns} */
	protected BigInteger v_s_p_logical;
	/** eval of P's derivative, simillary */
	protected BigInteger v_s_pd_logical;
	/** S_GCD(r) * r^{i*ns} */
	protected BigInteger v_s_gcd_logical;
	/** S_P_GCD(r) * r^{i*ns} */
	protected BigInteger v_s_p_gcd_logical;
	/** S_PD_GCD(r) * r^{i*ns} */
	protected BigInteger v_s_pd_gcd_logical;
	/** S_S(r) * r^{i*ns} */
	protected BigInteger v_s_s_logical;
	/** S_T(r) * r^{i*ns} */
	protected BigInteger v_s_t_logical;

	/** evaluation of partial polynomial T_P(r) * r^{i*nt} */
	protected BigInteger v_t_p_logical;
	/** eval of partial DERIVATIVE of P */
	protected BigInteger v_t_pd_logical;
	/** T_GCD(r) * r^{i*nt} */
	protected BigInteger v_t_gcd_logical;
	/** T_P_GCD(r) * r^{i*nt} */
	protected BigInteger v_t_p_gcd_logical;
	/** PD_GCD(r) * r^{i*nt} */
	protected BigInteger v_t_pd_gcd_logical;
	/** T_S(r) * r^{i*nt} */
	protected BigInteger v_t_s_logical;
	/** T_T(r) * r^{i*nt} */
	protected BigInteger v_t_t_logical;
	// the following are the corresponding input for the above
	protected BigInteger v_s_p_in_logical;
	protected BigInteger v_s_pd_in_logical;
	protected BigInteger v_s_gcd_in_logical;
	protected BigInteger v_s_p_gcd_in_logical;
	protected BigInteger v_s_pd_gcd_in_logical;
	protected BigInteger v_s_s_in_logical;
	protected BigInteger v_s_t_in_logical;
	protected BigInteger v_t_p_in_logical;
	protected BigInteger v_t_pd_in_logical;
	protected BigInteger v_t_gcd_in_logical;
	protected BigInteger v_t_p_gcd_in_logical;
	protected BigInteger v_t_pd_gcd_in_logical;
	protected BigInteger v_t_s_in_logical;
	protected BigInteger v_t_t_in_logical;

	protected Wire w_zero; //zero constant wire
	protected Wire w_one; //one constant wire


	// ******************************************************
	// ***  Utility Operations ***
	// ******************************************************

	/** set up the witness from arrInput. 
	Assumption: arrInput layed out as:
		arrStates (2n+1), 
		arrInput (2n), 
		arrBFail (2n), 
		arrAlignedInput(n), 
		Then the following 12 arrays are each of 
		S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T (size: ns)
		T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T, (size: nt)
		--- inputs in chunked_inputs.dat (see AccDriver) --- (37 elements)
		z, r1, r2
		hash_in, p_acc_states_in, p_acc_trans_in, 
		v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, vs_s, v_s_t_in,
		v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, vs_s_in, v_t_t_in,
		hash_out, p_acc_states, p_acc_trans
		v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, vs_s, v_s_t,
		v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, vs_s, v_t_t,

	Total: 7n + 38 + 6ns + 6nt
	*/	
	protected void setup_witness(Wire [] arrIn){
		int expected_len = getNumWitnessInputs();
		if(arrIn.length!=expected_len){
			Utils.fail("setup_witness: arrIn.len!=expected. len: " + arrIn.length + ", expected: " + expected_len);
		}

		int [] arrLen = new int [] {
			2*n+1, 2*n, 2*n, n,
			ns, ns, ns, ns, ns, ns,
			nt, nt, nt, nt, nt, nt,
			37	
		};
		Wire [] chunked_inputs = new Wire [37];
		Wire [][] arr2d = new Wire[][] {
			arrStates, this.arrInput, arrBFail, arrAlignedInput,
			S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T,
			T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T,
			chunked_inputs};
		int idx = 0;
		for(int i=0; i<arr2d.length; i++){
			int len = arrLen[i];
			Wire [] target = arr2d[i];
			for(int j=0; j<len; j++){
				target[j] = arrIn[idx];
				idx++;
			}
		}
		if(idx!=expected_len) {Utils.fail("setup_witness idx: " + idx + " != expected_len: " + expected_len + ", arrIn.len: " + arrIn.length);}

		this.z= chunked_inputs[0];
		this.r1= chunked_inputs[1];
		this.r2= chunked_inputs[2];
		this.hash_in= chunked_inputs[3];
		this.p_acc_states_in= chunked_inputs[4];
		this.p_acc_transitions_in= chunked_inputs[5];
		this.v_s_p_in= chunked_inputs[6];
		this.v_s_pd_in= chunked_inputs[7];
		this.v_s_gcd_in= chunked_inputs[8];
		this.v_s_p_gcd_in= chunked_inputs[9];
		this.v_s_pd_gcd_in= chunked_inputs[10];
		this.v_s_s_in= chunked_inputs[11];
		this.v_s_t_in= chunked_inputs[12];
		this.v_t_p_in= chunked_inputs[13];
		this.v_t_pd_in= chunked_inputs[14];
		this.v_t_gcd_in= chunked_inputs[15];
		this.v_t_p_gcd_in= chunked_inputs[16];
		this.v_t_pd_gcd_in= chunked_inputs[17];
		this.v_t_s_in= chunked_inputs[18];
		this.v_t_t_in= chunked_inputs[19];

		this.hash_out= chunked_inputs[20];
		this.p_acc_states_out= chunked_inputs[21];
		this.p_acc_transitions_out= chunked_inputs[22];
		this.v_s_p= chunked_inputs[23];
		this.v_s_pd= chunked_inputs[24];
		this.v_s_gcd= chunked_inputs[25];
		this.v_s_p_gcd= chunked_inputs[26];
		this.v_s_pd_gcd= chunked_inputs[27];
		this.v_s_s= chunked_inputs[28];
		this.v_s_t= chunked_inputs[29];
		this.v_t_p= chunked_inputs[30];
		this.v_t_pd= chunked_inputs[31];
		this.v_t_gcd= chunked_inputs[32];
		this.v_t_p_gcd= chunked_inputs[33];
		this.v_t_pd_gcd= chunked_inputs[34];
		this.v_t_s= chunked_inputs[35];
		this.v_t_t= chunked_inputs[36];
	}

	/** See the Wire version
	*/	
	protected void logical_setup_witness(BigInteger [] arrIn){
		int me = this.module_idx;
		int np = this.num_modules;
		int expected_len = getNumWitnessInputs();
		if(arrIn.length!=expected_len){
			Utils.fail("logical_setup_witness ERR: arrIn.len!=expected. len: " + arrIn.length + ", expected: " + expected_len);
		}

		int [] arrLen = new int [] {
			2*n+1, 2*n, 2*n, n,
			ns, ns, ns, ns, ns, ns,
			nt, nt, nt, nt, nt, nt,
			37	
		};
		BigInteger [] chunked_inputs = new BigInteger [37];
		BigInteger [][] arr2d = new BigInteger[][] {
			arrStates_logical, this.arrInput_logical, arrBFail_logical, arrAlignedInput_logical,
			S_P_logical, S_GCD_logical, S_P_GCD_logical, S_PD_GCD_logical, S_S_logical, S_T_logical,
			T_P_logical, T_GCD_logical, T_P_GCD_logical, T_PD_GCD_logical, T_S_logical, T_T_logical,
			chunked_inputs};
		int idx = 0;
		for(int i=0; i<arr2d.length; i++){
			int len = arrLen[i];
			BigInteger [] target = arr2d[i];
			for(int j=0; j<len; j++){
				target[j] = arrIn[idx];
				idx++;
			}
		}
		if(idx!=expected_len) {Utils.fail("logical_setup witness: idx: " + idx + " != expected_len: " + expected_len + ", arrIn.len: " + arrIn.length);}

		this.z_logical= chunked_inputs[0];
		this.r1_logical= chunked_inputs[1];
		this.r2_logical= chunked_inputs[2];
		this.hash_in_logical= chunked_inputs[3];
		this.p_acc_states_in_logical= chunked_inputs[4];
		this.p_acc_transitions_in_logical= chunked_inputs[5];
		this.v_s_p_in_logical= chunked_inputs[6];
		this.v_s_pd_in_logical= chunked_inputs[7];
		this.v_s_gcd_in_logical= chunked_inputs[8];
		this.v_s_p_gcd_in_logical= chunked_inputs[9];
		this.v_s_pd_gcd_in_logical= chunked_inputs[10];
		this.v_s_s_in_logical= chunked_inputs[11];
		this.v_s_t_in_logical= chunked_inputs[12];
		this.v_t_p_in_logical= chunked_inputs[13];
		this.v_t_pd_in_logical= chunked_inputs[14];
		this.v_t_gcd_in_logical= chunked_inputs[15];
		this.v_t_p_gcd_in_logical= chunked_inputs[16];
		this.v_t_pd_gcd_in_logical= chunked_inputs[17];
		this.v_t_s_in_logical= chunked_inputs[18];
		this.v_t_t_in_logical= chunked_inputs[19];

		this.hash_out_logical= chunked_inputs[20];
		this.p_acc_states_out_logical= chunked_inputs[21];
		this.p_acc_transitions_out_logical= chunked_inputs[22];
		this.v_s_p_logical= chunked_inputs[23];
		this.v_s_pd_logical= chunked_inputs[24];
		this.v_s_gcd_logical= chunked_inputs[25];
		this.v_s_p_gcd_logical= chunked_inputs[26];
		this.v_s_pd_gcd_logical= chunked_inputs[27];
		this.v_s_s_logical= chunked_inputs[28];
		this.v_s_t_logical= chunked_inputs[29];
		this.v_t_p_logical= chunked_inputs[30];
		this.v_t_pd_logical= chunked_inputs[31];
		this.v_t_gcd_logical= chunked_inputs[32];
		this.v_t_p_gcd_logical= chunked_inputs[33];
		this.v_t_pd_gcd_logical= chunked_inputs[34];
		this.v_t_s_logical= chunked_inputs[35];
		this.v_t_t_logical= chunked_inputs[36];
	}


	/** produce the value of:
		(r+a[0])...(r+a[n]) 
		This the clear-text (exponent) part of Ngyen's bilinear accumulator
		Assumption: a.length greater than 0 
	*/
	protected Wire build_bin_acc(Wire [] a, Wire r){
		Wire res = a[0].add(r);
		for(int i=1; i<a.length; i++){
			res = res.mul(a[i].add(r));
		} 	
		return res;
	}

	/** logical version of build_bin_acc */
	public BigInteger logical_build_bin_acc(BigInteger [] a, BigInteger r){
		BigInteger modulus = this.config.getFieldOrder();
		for(int i=0; i<a.length; i++){
		}
		BigInteger res = a[0].add(r);
		for(int i=1; i<a.length; i++){
			res = res.multiply(a[i].add(r)).mod(modulus);
		} 	
		return res.mod(modulus);
	}

	/** treat a as a coef vector of polynomial
		p(x) = a[0] + a[1]*x + a[2]*x^2 + ... a[n-1]*x^{n-1}
		evaluate and return p(r) * base
	*/
	protected Wire eval_poly(Wire [] a, Wire r, Wire base){
		int n = a.length-1;
		Wire res = a[n];
		for(int i=1; i<a.length; i++){
			res = res.mul(r).add(a[n-i]);
		} 	
		return res.mul(base);
	}

	/** logical version of eval_poly */
	protected BigInteger logical_eval_poly(BigInteger [] a, BigInteger r, BigInteger base){
		int n = a.length-1;
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger res = a[n];
		for(int i=1; i<a.length; i++){
			res = res.multiply(r).add(a[n-i]).mod(modulus);
		} 	
		return res.multiply(base).mod(modulus);
	}


	/** Let a be the coefs vector for a polynomial p(x).
	Return the coefs vector of polynomial q() s.t.:
	q(x) = x^base p'(x) where p'(x) is the derivative of p(x)
	BUT, since the trailing base items are 0, only return the
	first n items where n = |p(x)| (coefs length).

	Let the result be b[0], ..., b[n].
	The resulting polynomial is actually x^(base-1) (b[0]*x^0 + ... b[n]*x^n)

		Example: base = 3 and p(x) = (3x^2 + 2x + 1) * x^3. The input vector is
		[1, 2, 3]
		p'(x) = 15x^4 + 8x^3 + 3x^2 
			  = x^2(3 + 8x + 15x^2)
		The returned vector is [3, 8, 15]

		Example: base = 0 and p(x) = (3x^2 + 2x + 1) * x^0. The input vec is [1, 2, 3]
		p'(x) = 6x + x = x^-1(6x^2 + x + 0)
		The returned vector b is [0, 1, 6] 	
	*/
	protected Wire [] get_derivative_shifted(Wire [] a, int base){
		int n = a.length;
		Wire [] b = new Wire [n];
		for(int i=0; i<n; i++){
			Wire factor = generator.createConstantWire(i+base);
			b[i] = a[i].mul(factor);
		}
		//let q(x) = b[0]*x^0 + ... b[n]*x^n
		//the actual returned poly is x^{base-1} * q(x)
		return b; 
	}

	/** logical version of get_derivative_shifted  (see doc for examples)
	*/
	public BigInteger [] logical_get_derivative_shifted(BigInteger [] a, int base){
		int n = a.length;
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger [] b = new BigInteger [n];
		for(int i=0; i<n; i++){
			BigInteger factor = Utils.itobi(i+base);
			b[i] = a[i].multiply(factor).mod(modulus);
		}
		return b; 
	}

	/** each transition t[i] = chars[i]*2^{2*bitwidth+1} + states[i]*2^{bitwidth+1] +state[i+1]*2 + bFail + 2^62. 
	See also nfa/ac/AC.java::digitizeTransition()
	*/
	protected BigInteger pow1 = null;
	protected BigInteger pow2 = null;
	protected BigInteger two = null;
	protected Wire [] build_trans(Wire [] states, Wire [] chars, Wire [] bFail){
		BigInteger pow62 = BigInteger.valueOf(1).shiftLeft(62);
		int n = chars.length;
		if(states.length!=n+1){Utils.fail("statse.length!=n+1");}
		Wire [] trans = new Wire [n]; //transition set
		if(two==null){
			two = Utils.itobi(2);
			pow1 = two.pow(this.state_bits + 1);
			pow2 = two.pow(this.state_bits*2 + 1);
		}
		for(int i=0; i<n; i++){
			trans[i] = bFail[i].add(
				states[i+1].mul(two).add(
					chars[i].mul(pow2).add(
						states[i].mul(pow1)
					)
				)
			).add(pow62);
		}
		return trans;
	}

	/** each transition t[i] = chars[i]*2^{2*bitwidth+1} + states[i]*2^{bitwidth+1] +state[i+1]*2 + bFail[i] + 2^62*/
	public BigInteger [] logical_build_trans(BigInteger [] states, BigInteger [] chars, BigInteger [] bFail ){
		BigInteger pow62 = BigInteger.valueOf(1).shiftLeft(62);
		int n = chars.length;
		if(states.length!=n+1){Utils.fail("statse.length!=n+1");}
		BigInteger [] trans = new BigInteger [n]; //transition set
		if(two==null){
			two = Utils.itobi(2);
			pow1 = two.pow(this.state_bits + 1);
			pow2 = two.pow(this.state_bits*2 + 1);
		}
		for(int i=0; i<n; i++){
			trans[i] = bFail[i].add(
				states[i+1].multiply(two).add(
					chars[i].multiply(pow2).add(
						states[i].multiply(pow1)
					)
				)
			).add(pow62);
		}
		return trans;
	}

	/** Given a[] is an array of 4-bit numbers, build
		an array of 252-bit numbers (to accompodate bn254). 
		The size of the returned array is ceil(a.length/63). 
		Each a[i] is split into 4-bit wires and (verified it's indeed
		4-bit), and then every 252-bit is grouped
	*/
	protected Wire [] build_252bit(Wire [] a){
		int total_bits = a.length*4;
		int len = total_bits%252==0? total_bits/252: total_bits/252 + 1;
		Wire [] bits = new Wire [total_bits];
		Wire [] res = new Wire [len];

		//1. split into ALL bits (verification included)
		for(int i=0; i<a.length; i++){
			Wire [] wa = a[i].getBitWires(4).asArray();
			for(int j=0; j<4; j++){
				bits[i*4 + j] = wa[j];
			}
		}

		//2. merge every 252 bits
		for(int i=0; i<len; i++){
			int start = i*252;
			int end = (i+1)*252>=total_bits? total_bits: (i+1)*252; //not inc.
			WireArray wa = new WireArray(Arrays.copyOfRange(
				bits, start, end));
			res[i] = wa.packAsBits();
		}
		return res;
	}

	/** logical verison of build_252bit
	*/
	protected BigInteger [] logical_build_252bit(BigInteger [] a){
		int total_bits = a.length*4;
		int len = total_bits%252==0? total_bits/252: total_bits/252 + 1;
		BigInteger [] bits = new BigInteger [total_bits];
		BigInteger [] res = new BigInteger [len];

		//1. split into ALL bits (verification included)
		for(int i=0; i<a.length; i++){
			BigInteger [] wa = Util.split(a[i], 4, 1);
			for(int j=0; j<4; j++){
				bits[i*4 + j] = wa[j];
			}
		}

		//2. merge every 252 bits
		BigInteger modulus = this.config.getFieldOrder(); 
		for(int i=0; i<len; i++){
			int start = i*252;
			int end = (i+1)*252>=total_bits? total_bits: (i+1)*252; //not inc.
			res[i] = Util.group(Arrays.copyOfRange(
				bits, start, end), 1).mod(modulus);
		}
		return res;
	}


	/** Construct the Poseidon hash of arrAlignedInput
		Assumption: length of arrAlignedInput should be a multiple
		of 64. This is because each char in arrAlignedInput is
		4-bit. 256 = 4*64 (which is ONE input line of Poseidon).
	*/
	protected Wire build_hash(Wire [] arrAlignedInput, Wire hash_in){
		//1. pack every 64 elements of arrAlignedInput as a 252-bit number
		Wire [] arr252bits = build_252bit(arrAlignedInput);

		//2. hash the arr252bitInt 
		ZaHash2 hash = new ZaPoseidon(config, (ZaGenerator) this.generator);
        Wire res = hash_in;
		for(int i=0; i<arr252bits.length; i++){
			hash = ZaHash2.new_hash(config, (ZaGenerator) this.generator);
        	hash.build_circuit(new Wire [] {}, 
				new Wire [] {res, arr252bits[i]});
        	res = hash.getOutputWires()[0];
			
		}
		return res;
	}

	public BigInteger logical_build_hash(BigInteger [] arrAlignedInput, BigInteger hash_in){
		//1. pack every 64 elements of arrAlignedInput as a 252-bit number
		BigInteger [] arr252bits = logical_build_252bit(arrAlignedInput);

		//2. hash the arr252bitInt 
		ZaHash2 hash = new ZaPoseidon(config, (ZaGenerator) this.generator);
        BigInteger res = hash_in;
		for(int i=0; i<arr252bits.length; i++){
			res = hash.hash2(res, arr252bits[i]);
		}
		return res;
	}

	// assert all elements are boolean bits
	public void logical_assert_boolean(BigInteger [] arrB){
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);
		for(int i=0; i<arrB.length; i++){
			if(!arrB[i].equals(one) && !arrB[i].equals(zero)){
				Utils.fail("arrB[" + i + "] is not booean!");
			}
		}
	}


	// assert all elements are boolean bits
	public void assert_boolean(Wire [] arrB){
		for(int i=0; i<arrB.length; i++){
			this.generator.addBinaryAssertion(arrB[i]);
		}
	}

	// b: arrBFail, a: arrInput
	// if b[i-1] is set then a[i] = a[i-1]
	// check for index>=1 (excluding 0)
	// assumption: b[] is already asserted to be all boolean
	// Idea: arithemtic the following expression:
	//  if b[i-1] then { return a[i]==a[i-1]}  else { return 1;}
	// b[i-1]*(1-(a[i]-a[i-1]) + (1-b[i-1]) is VALUE 1
	public void assert_valid_fail_edges(Wire [] b, Wire [] a){
		for(int i=1; i<b.length; i++){
			Wire val = w_one.sub(b[i-1]).add(
				b[i-1].mul( w_one.sub(a[i]).add(a[i-1]) )
			);
			this.generator.addOneAssertion(val, "assert_valid_inputs");
		}
	}

	// logical version of assert_valid_inputs
	// when b[i-1] is set then a[i] = a[i-1] for fail edges
	// here b[i-1] is arrBFail, and a[] is arrInput
	public void logical_assert_valid_fail_edges(BigInteger [] b, BigInteger [] a){
		BigInteger w_one = Utils.itobi(1);
		BigInteger w_zero= Utils.itobi(0);
		for(int i=1; i<b.length; i++){
			BigInteger val = w_one.subtract(b[i-1]).add(
				b[i-1].multiply(w_one.subtract(a[i]).add(a[i-1]))
			);
			if(!val.equals(w_one)){
				Utils.fail("logical_assert_valid_inputs fail at index " + i);
			}
		}
	}

	// assert that a2 is a valid aligned array of a1.
	// Idea: build two polynomials based on a1 and a2 and compare
	// their values.
	// E.g. n = 2
	// a1 = 2    2     3    3 
    // b  = 0    1     0    1    (1 means fail edge)
	// nb = 1    0     1    0    (negation of b)
	// a2 = 2    3
    // r1 = r^0  0     r^1  0 
	// r2 = r^0  r^1   r^2  r^3
	// r3 = r^0  r^0   r^1  r^1
    // p1 = SUM a1[i]*r1[i]  = 2r^0 + 3r^1 
	// p2 = SUM a2[i]*r2[i] = 2r^0 + 3r^1
	public void assert_valid_aligned_old(Wire [] a1, Wire [] a2, Wire [] b, Wire r){
		int n = a2.length; //asumming a1 is 2n, b is 2n
		Wire [] r1 = new Wire [2*n];
		Wire [] r2 = new Wire [2*n];
		Wire [] r3 = new Wire [2*n];
		Wire [] nb = new Wire [2*n]; //neg_b
		r1[0] = w_one;
		r2[0] = w_one;
		r3[0] = w_one;

		for(int i=0; i<2*n; i++){
			nb[i] = w_one.sub(b[i]);
		}
		for(int i=1; i<2*n; i++){
			r2[i] = r2[i-1].mul(r);
			r3[i] = r3[i-1].mul(nb[i]).mul(r).add(
				b[i].mul(r3[i-1]) );
			r1[i] = r3[i].mul(nb[i]);
		}

		Wire p1 = w_one;
		Wire p2 = w_one;
		for(int i=0; i<2*n; i++){
			p1 = p1.add(a1[i].mul(r1[i]));
		}
		for(int i=0; i<n; i++){
			p2 = p2.add(a2[i].mul(r2[i]));
		}
		this.generator.addEqualityAssertion(p1, p2, "assert_valid_aligned");
	}

	// assert that a2 is a valid aligned array of a1.
	// Idea: build two polynomials based on a1 and a2 and compare
	// their values.
	// E.g. n = 2
	// a1 = 2    2     3    3 
    // b  = 0    1     0    1    (1 means fail edge)
	// nb = 1    0     1    0    (negation of b)
	// a2 = 2    3
    // r1 = r^0  0     r^1  0 
	// r2 = r^0  r^1   r^2  r^3
	// r3 = r^0  r^0   r^1  r^1
    // p1 = SUM a1[i]*r1[i]  = 2r^0 + 3r^1 
	// p2 = SUM a2[i]*r2[i] = 2r^0 + 3r^1
	// THIS NEW VERSION computes p2 by the recursive formula given
	// in the paper.
	public void assert_valid_aligned(Wire [] a1, Wire [] a2, Wire [] b, Wire r){
		int n = a2.length; //asumming |a1| is 2n, |b| is 2n, and |a2| is n
		Wire p1 = a2[n-1];
		for(int i=0; i<n-1; i++){
			p1 = p1.mul(r).add(a2[n-i-2]);
		}

		Wire p2 = w_one.sub(b[2*n-1]).mul(a1[2*n-1]);
		for(int i=0; i<2*n-1; i++){
			p2 = b[2*n-i-2].mul(p2).add(w_one.sub(b[2*n-i-2]).mul(p2.mul(r).add(a1[2*n-i-2])));
		}
		this.generator.addEqualityAssertion(p1, p2, "assert_valid_aligned");
	}

	public void logical_assert_valid_aligned(BigInteger [] a1, BigInteger [] a2, BigInteger [] b, BigInteger r){
		int n = a2.length; //asumming |a1| is 2n, |b| is 2n, and |a2| is n
		BigInteger w_one = Utils.itobi(1);
		BigInteger p1 = a2[n-1];
		BigInteger modulus = this.config.getFieldOrder();

		//1. Horner's polynomial evaluation method to eval: a2(r)
		//p1 = (((a2[n-1])*r + a2[n-2])*r + a2[n-3])...a2[1])*r + a2[0]
		for(int i=0; i<n-1; i++){
			p1 = p1.multiply(r).add(a2[n-i-2]).mod(modulus);
		}

		//2. Horner's polynomial eval to evaluate a1(r) but using b[] as 
		//flag of failing edges 
		BigInteger p2 = w_one.subtract(b[2*n-1]).multiply(a1[2*n-1]);
		for(int i=0; i<2*n-1; i++){
			//2.1 if b[2*n-i-2] is true (fail edge), keep p2
			p2 = b[2*n-i-2].multiply(p2).add(
			//2.2. otherwise (not fail): p2 = p2*r + a1[2*n-i-2] 
					w_one.subtract(b[2*n-i-2]).
					multiply(p2.multiply(r).add(a1[2*n-i-2]))
			).mod(modulus);
		}
		logical_addEqualityAssertion(p1, p2, "Logical_assert_valid_aligned");
	}

	/** assert that v1 = v2 */
	private void logical_addEqualityAssertion(BigInteger v1, BigInteger v2, String msg){
		if(!v1.equals(v2)){
			System.out.println("v1: " + v1 + ", v2: "  + v2);
			Utils.fail("ERROR: " + msg);
		}
	}

	/** verify r and r_inv are indeed inverse of each other */
	protected void logical_assert_r_inv(BigInteger r, BigInteger r_inv){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger prod_r = r.multiply(r_inv).mod(modulus);
		BigInteger one = Utils.itobi(1);
		logical_addEqualityAssertion(prod_r, one, "r*r_inv!=1");
	}

	/** verify r and r_inv are indeed inverse of each other */
	protected void assert_r_inv(Wire r, Wire r_inv){
		Wire prod_r = r.mul(r_inv);
		Wire one = generator.createConstantWire(1);
		generator.addEqualityAssertion(prod_r, one, "r*r_inv!=1");
	}

	/** assert the validty of chunk inputs and the supplied outputs
	Basically the following
	poly related chunk inputs/outputs, and the hash_in/out will be checked:

	p_acc_states_in: (r+s1)(r+s2) ... (r+sn)
	p_acc_transitions_in: (r+t1)* ... *(r+tn)
	hash_in: the input hash for chaining hash
	v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, v_s_s_in, v_s_t_in,
	v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, v_t_s_in, v_t_t_in,
	
	p_acc_states_out: (r+s1)(r+s2) ... (r+sn)
	p_acc_transitions_out: (r+t1)* ... *(r+tn)
	hash_out: the hash of all input characters in arrAlignedInput.
		Note: if the input is less than the circuit size, padd it with 0.
	v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_pd_gcd, v_s_s, v_s_t, 
	v_t_p, v_t_pd, v_t_gcd, v_t_v_gcd, v_t_pd_gcd, v_t_s, v_t_t
	 */
	protected void logical_assert_chunk_polys(
		int n, //size of this chunk of input strings
		int ns, //chunk size for state related polynomials
		int nt, //chunk size for transitions related polynomials 

		BigInteger [] arrStates_logical,
		BigInteger r_logical,
		BigInteger [] arrInput_logical,
		BigInteger [] arrBFail_logical,
		BigInteger [] arrAlignedInput_logical,
		BigInteger [] S_P_logical,
		BigInteger [] S_GCD_logical,
		BigInteger [] S_P_GCD_logical,
		BigInteger [] S_PD_GCD_logical,
		BigInteger [] S_S_logical,
		BigInteger [] S_T_logical,
		BigInteger [] T_P_logical,
		BigInteger [] T_GCD_logical,
		BigInteger [] T_P_GCD_logical,
		BigInteger [] T_PD_GCD_logical,
		BigInteger [] T_S_logical,
		BigInteger [] T_T_logical,

		BigInteger hash_in_logical,
		BigInteger v_s_p_in_logical, 
		BigInteger v_s_pd_in_logical, 
		BigInteger v_s_gcd_in_logical, 
		BigInteger v_s_p_gcd_in_logical, 
		BigInteger v_s_pd_gcd_in_logical, 
		BigInteger v_s_s_in_logical, 
		BigInteger v_s_t_in_logical, 
		BigInteger v_t_p_in_logical, 
		BigInteger v_t_pd_in_logical, 
		BigInteger v_t_gcd_in_logical, 
		BigInteger v_t_p_gcd_in_logical, 
		BigInteger v_t_pd_gcd_in_logical, 
		BigInteger v_t_s_in_logical, 
		BigInteger v_t_t_in_logical, 

		BigInteger hash_out_logical,
		BigInteger v_s_p_out_logical, 
		BigInteger v_s_pd_out_logical, 
		BigInteger v_s_gcd_out_logical, 
		BigInteger v_s_p_gcd_out_logical, 
		BigInteger v_s_pd_gcd_out_logical, 
		BigInteger v_s_s_out_logical, 
		BigInteger v_s_t_out_logical, 
		BigInteger v_t_p_out_logical, 
		BigInteger v_t_pd_out_logical, 
		BigInteger v_t_gcd_out_logical, 
		BigInteger v_t_p_gcd_out_logical, 
		BigInteger v_t_pd_gcd_out_logical, 
		BigInteger v_t_s_out_logical, 
		BigInteger v_t_t_out_logical 
	){
		//1. compute EXPECTED values
		//1.1 p_acc_states, p_acc_trans, and hash
		BigInteger modulus = config.getFieldOrder();
		BigInteger exp_p_acc_states_out_logical= logical_build_bin_acc(arrStates_logical, r_logical).multiply(p_acc_states_in_logical).mod(modulus);
		BigInteger exp_acc_transitions_out_logical= logical_build_bin_acc(logical_build_trans(arrStates_logical, arrInput_logical, arrBFail_logical), r_logical).multiply(p_acc_transitions_in_logical).mod(modulus);
		BigInteger exp_hash_out_logical = logical_build_hash(arrAlignedInput_logical, hash_in_logical);

		int exp_base_s = module_idx * (NS/num_modules);
		int exp_base_t = module_idx * (NT/num_modules);
		BigInteger base_t = wire_pow(r_logical, r_inv_logical, exp_base_t);
		BigInteger base_s = wire_pow(r_logical, r_inv_logical, exp_base_s);
		BigInteger base_s_1 = wire_pow(r_logical, r_inv_logical, exp_base_s-1);
		BigInteger base_t_1 = wire_pow(r_logical, r_inv_logical, exp_base_t-1);

		//1.2 v_s_p, ... related to states polynomials
		BigInteger exp_v_s_p_logical = logical_eval_poly(S_P_logical, r_logical, base_s).add(v_s_p_in_logical).mod(modulus);
		BigInteger [] S_PD_logical = logical_get_derivative_shifted(S_P_logical, exp_base_s);
		BigInteger exp_v_s_pd_logical = logical_eval_poly(S_PD_logical, r_logical, base_s_1).add(v_s_pd_in_logical).mod(modulus);
;
		BigInteger exp_v_s_gcd_logical = logical_eval_poly(S_GCD_logical, r_logical, base_s).add(v_s_gcd_in_logical).mod(modulus);
		BigInteger exp_v_s_p_gcd_logical = logical_eval_poly(S_P_GCD_logical, r_logical, base_s).add(v_s_p_gcd_in_logical).mod(modulus);
		BigInteger exp_v_s_pd_gcd_logical = logical_eval_poly(S_PD_GCD_logical, r_logical, base_s).add(v_s_pd_gcd_in_logical).mod(modulus);
		BigInteger exp_v_s_s_logical = logical_eval_poly(S_S_logical, r_logical, base_s).add(v_s_s_in_logical).mod(modulus);
		BigInteger exp_v_s_t_logical = logical_eval_poly(S_T_logical, r_logical, base_s).add(v_s_t_in_logical).mod(modulus);

		//1.3 v_t_p ... related to states polynomials
		BigInteger exp_v_t_p_logical = logical_eval_poly(T_P_logical, r_logical, base_t).add(v_t_p_in_logical).mod(modulus);

		BigInteger [] T_PD_logical = logical_get_derivative_shifted(T_P_logical, exp_base_t);
		BigInteger exp_v_t_pd_logical = logical_eval_poly(T_PD_logical, r_logical, base_t_1).add(v_t_pd_in_logical).mod(modulus);
		BigInteger exp_v_t_gcd_logical = logical_eval_poly(T_GCD_logical, r_logical, base_t).add(v_t_gcd_in_logical).mod(modulus);
		BigInteger exp_v_t_p_gcd_logical = logical_eval_poly(T_P_GCD_logical, r_logical, base_t).add(v_t_p_gcd_in_logical).mod(modulus);
		BigInteger exp_v_t_pd_gcd_logical = logical_eval_poly(T_PD_GCD_logical, r_logical, base_t).add(v_t_pd_gcd_in_logical).mod(modulus);
		BigInteger exp_v_t_s_logical = logical_eval_poly(T_S_logical, r_logical, base_t).add(v_t_s_in_logical).mod(modulus);
		BigInteger exp_v_t_t_logical = logical_eval_poly(T_T_logical, r_logical, base_t).add(v_t_t_in_logical).mod(modulus);


		//2. assert the validity
		BigInteger [][] pairs = new BigInteger [][] {
			{exp_hash_out_logical, hash_out_logical},

			{exp_v_s_p_logical, v_s_p_logical},
			{exp_v_s_pd_logical, v_s_pd_logical},
			{exp_v_s_gcd_logical, v_s_gcd_logical},
			{exp_v_s_p_gcd_logical, v_s_p_gcd_logical},
			{exp_v_s_pd_gcd_logical, v_s_pd_gcd_logical},
			{exp_v_s_s_logical, v_s_s_logical},
			{exp_v_s_t_logical, v_s_t_logical},

			{exp_v_t_p_logical, v_t_p_logical},
			{exp_v_t_pd_logical, v_t_pd_logical},
			{exp_v_t_gcd_logical, v_t_gcd_logical},
			{exp_v_t_p_gcd_logical, v_t_p_gcd_logical},
			{exp_v_t_pd_gcd_logical, v_t_pd_gcd_logical},
			{exp_v_t_s_logical, v_t_s_logical},
			{exp_v_t_t_logical, v_t_t_logical},
		};
		String [] names = new String [] {
			"hash_out_logical", 

			"v_s_p_logical",
			"v_s_pd_logical",
			"v_s_gcd_logical",
			"v_s_p_gcd_logical",
			"v_s_pd_gcd_logical",
			"v_s_s_logical",
			"v_s_t_logical",

			"v_t_p_logical",
			"v_t_pd_logical",
			"v_t_gcd_logical",
			"v_t_p_gcd_logical",
			"v_t_pd_gcd_logical",
			"v_t_s_logical",
			"v_t_t_logical",
		};
		for(int i=0; i<pairs.length; i++){
			logical_addEqualityAssertion(pairs[i][0], pairs[i][1], "FAILS on checking: " + names[i] + ". Expected: " + pairs[i][0] + ", actual: " + pairs[i][1]);
		}

	}

	/** See the logical_ version */
	protected void assert_chunk_polys(
		int n, //size of this chunk of input strings
		int ns, //chunk size for state related polynomials
		int nt, //chunk size for transitions related polynomials 

		Wire [] arrStates,
		Wire r,
		Wire [] arrInput,
		Wire [] arrBFail,
		Wire [] arrAlignedInput,
		Wire [] S_P,
		Wire [] S_GCD,
		Wire [] S_P_GCD,
		Wire [] S_PD_GCD,
		Wire [] S_S,
		Wire [] S_T,
		Wire [] T_P,
		Wire [] T_GCD,
		Wire [] T_P_GCD,
		Wire [] T_PD_GCD,
		Wire [] T_S,
		Wire [] T_T,

		Wire hash_in,
		Wire v_s_p_in, 
		Wire v_s_pd_in, 
		Wire v_s_gcd_in, 
		Wire v_s_p_gcd_in, 
		Wire v_s_pd_gcd_in, 
		Wire v_s_s_in, 
		Wire v_s_t_in, 
		Wire v_t_p_in, 
		Wire v_t_pd_in, 
		Wire v_t_gcd_in, 
		Wire v_t_p_gcd_in, 
		Wire v_t_pd_gcd_in, 
		Wire v_t_s_in, 
		Wire v_t_t_in, 

		Wire hash_out,
		Wire v_s_p_out, 
		Wire v_s_pd_out, 
		Wire v_s_gcd_out, 
		Wire v_s_p_gcd_out, 
		Wire v_s_pd_gcd_out, 
		Wire v_s_s_out, 
		Wire v_s_t_out, 
		Wire v_t_p_out, 
		Wire v_t_pd_out, 
		Wire v_t_gcd_out, 
		Wire v_t_p_gcd_out, 
		Wire v_t_pd_gcd_out, 
		Wire v_t_s_out, 
		Wire v_t_t_out 
	){
		//1. compute EXPECTED values
		//1.1 p_acc_states, p_acc_trans, and hash
		Wire exp_p_acc_states_out= build_bin_acc(arrStates, r).mul(p_acc_states_in);
		Wire exp_acc_transitions_out= build_bin_acc(build_trans(arrStates, arrInput, arrBFail), r).mul(p_acc_transitions_in);
		Wire exp_hash_out = build_hash(arrAlignedInput, hash_in);

		int exp_base_s = module_idx * (NS/num_modules);
		int exp_base_t = module_idx * (NT/num_modules);
		Wire base_t = wire_pow(r, r_inv, exp_base_t);
		Wire base_s = wire_pow(r, r_inv, exp_base_s);
		Wire base_s_1 = wire_pow(r, r_inv, exp_base_s-1);
		Wire base_t_1 = wire_pow(r, r_inv, exp_base_t-1);

		//1.2 v_s_p, ... related to states polynomials
		Wire exp_v_s_p = eval_poly(S_P, r, base_s).add(v_s_p_in);
		Wire [] S_PD = get_derivative_shifted(S_P, exp_base_s);
		Wire exp_v_s_pd = eval_poly(S_PD, r, base_s_1).add(v_s_pd_in);
;
		Wire exp_v_s_gcd = eval_poly(S_GCD, r, base_s).add(v_s_gcd_in);
		Wire exp_v_s_p_gcd = eval_poly(S_P_GCD, r, base_s).add(v_s_p_gcd_in);
		Wire exp_v_s_pd_gcd = eval_poly(S_PD_GCD, r, base_s).add(v_s_pd_gcd_in);
		Wire exp_v_s_s = eval_poly(S_S, r, base_s).add(v_s_s_in);
		Wire exp_v_s_t = eval_poly(S_T, r, base_s).add(v_s_t_in);

		//1.3 v_t_p ... related to states polynomials
		Wire exp_v_t_p = eval_poly(T_P, r, base_t).add(v_t_p_in);
		Wire [] T_PD = get_derivative_shifted(T_P, exp_base_t);
		Wire exp_v_t_pd = eval_poly(T_PD, r, base_t_1).add(v_t_pd_in);
;
		Wire exp_v_t_gcd = eval_poly(T_GCD, r, base_t).add(v_t_gcd_in);
;
		Wire exp_v_t_p_gcd = eval_poly(T_P_GCD, r, base_t).add(v_t_p_gcd_in);
		Wire exp_v_t_pd_gcd = eval_poly(T_PD_GCD, r, base_t).add(v_t_pd_gcd_in);
		Wire exp_v_t_s = eval_poly(T_S, r, base_t).add(v_t_s_in);
		Wire exp_v_t_t = eval_poly(T_T, r, base_t).add(v_t_t_in);

		//2. assert the validity
		Wire [][] pairs = new Wire [][] {
			{exp_hash_out, hash_out},

			{exp_v_s_p, v_s_p},
			{exp_v_s_pd, v_s_pd},
			{exp_v_s_gcd, v_s_gcd},
			{exp_v_s_p_gcd, v_s_p_gcd},
			{exp_v_s_pd_gcd, v_s_pd_gcd},
			{exp_v_s_s, v_s_s},
			{exp_v_s_t, v_s_t},

			{exp_v_t_p, v_t_p},
			{exp_v_t_pd, v_t_pd},
			{exp_v_t_gcd, v_t_gcd},
			{exp_v_t_p_gcd, v_t_p_gcd},
			{exp_v_t_pd_gcd, v_t_pd_gcd},
			{exp_v_t_s, v_t_s},
			{exp_v_t_t, v_t_t},
		};
		String [] names = new String [] {
			"hash_out", 

			"v_s_p",
			"v_s_pd",
			"v_s_gcd",
			"v_s_p_gcd",
			"v_s_pd_gcd",
			"v_s_s",
			"v_s_t",

			"v_t_p",
			"v_t_pd",
			"v_t_gcd",
			"v_t_p_gcd",
			"v_t_pd_gcd",
			"v_t_s",
			"v_t_t",
		};
		for(int i=0; i<pairs.length; i++){
			generator.addEqualityAssertion(pairs[i][0], pairs[i][1], "FAILS on checking: " + names[i] + ". Expected: " + pairs[i][0] + ", actual: " + pairs[i][1]);
		}
	}

	/** Basically check set_support: bizout's relations */
	public void logical_assert_set_support(String set_name,
		BigInteger v_p,  
		BigInteger v_pd,  
		BigInteger v_gcd,  
		BigInteger v_p_gcd, 
		BigInteger v_pd_gcd, 
		BigInteger v_s, 
		BigInteger v_t){

		BigInteger modulus = this.config.getFieldOrder();
		//1. check p_gcd UNION gcd = p 
		BigInteger prod_gcd_p_gcd = v_gcd.multiply(v_p_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_gcd_p_gcd, v_p, "(p-gcd) * gcd !=p for " + set_name);

		//2 check pd_gcd UNION gcd = pd (for set states) 
		BigInteger prod_gcd_pd_gcd = v_gcd.multiply(v_pd_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_gcd_pd_gcd, v_pd, "(pd-gcd) * gcd !=pd for " + set_name);

		//3 check p_gcd and pd_gcd are disjoint (for set states);
		BigInteger one = Utils.itobi(1);
		BigInteger bizout_p_gcd_pd_gcd = v_p_gcd.multiply(v_s).add(v_pd_gcd.multiply(v_t)).mod(modulus);
		logical_addEqualityAssertion(bizout_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for " + set_name);
	}

	/** Basically check set_support: bizout's relations */
	public void assert_set_support(String set_name,
		Wire v_p,  
		Wire v_pd,  
		Wire v_gcd,  
		Wire v_p_gcd, 
		Wire v_pd_gcd, 
		Wire v_s, 
		Wire v_t){

		//1. check p_gcd UNION gcd = p 
		Wire prod_gcd_p_gcd = v_gcd.mul(v_p_gcd);
		generator.addEqualityAssertion(prod_gcd_p_gcd, v_p, "(p-gcd) * gcd !=p for " + set_name);

		//2 check pd_gcd UNION gcd = pd (for set states) 
		Wire prod_gcd_pd_gcd = v_gcd.mul(v_pd_gcd);
		generator.addEqualityAssertion(prod_gcd_pd_gcd, v_pd, "(pd-gcd) * gcd !=pd for " + set_name);

		//3 check p_gcd and pd_gcd are disjoint (for set states);
		Wire one = generator.createConstantWire(1);
		Wire bizout_p_gcd_pd_gcd = v_p_gcd.mul(v_s).add(v_pd_gcd.mul(v_t));
		generator.addEqualityAssertion(bizout_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for " + set_name);
	}

	/** compute wire^exp. up to 64 levels of recursion. handles -1, but not others*/
	protected Wire wire_pow(Wire wire, Wire inv, long exp){
		if(exp<-1) { throw new RuntimeException("exp cannot be negative!");}
		if(exp==-1) {return inv;}
		if(exp==0){ return this.generator.createConstantWire(1);}
		else if(exp%2==0){return wire_pow(wire.mul(wire),inv, exp/2);}
		else{
			return wire.mul( wire_pow(wire.mul(wire), inv, (exp-1)/2) );
		}
	}

	/* we only handle -1, 0, and positive 64-bits */
	protected BigInteger wire_pow(BigInteger wire, BigInteger inv, long exp){
		if(exp<-1) { throw new RuntimeException("exp cannot be negative!");}
		if(exp==-1) {return inv;}
		BigInteger modulus = this.config.getFieldOrder();
		if(exp==0){ return Utils.itobi(1);}
		else if(exp%2==0){return wire_pow(wire.multiply(wire).mod(modulus), inv, exp/2);}
		else{
			return wire.multiply( wire_pow(wire.multiply(wire).mod(modulus), inv, (exp-1)/2) ).mod(modulus);
		}
	}


	// ***********************************************************
	// 		PUBLIC OPERATIONS
	// ***********************************************************
	/* chunks_252bit: each node will have input stream in chunks of 252 bit.
		this parameter sets the number of 252bit chunks.
		np: number of processors.
		idx: the idx of the module to generate */
	public static ZaModularVerifierV3 new_ZaModularVerifierV3(ZaConfig cfg, int chunks_252bit, int idx, int np){
		int n = chunks_252bit * (252/4);
		int total_len = np * n;
		int alphabet_bits = 4;
		ZaModularVerifierV3 za= new ZaModularVerifierV3(cfg, null, 
			total_len , 4, idx, np, 128);
		return za;
	}

	/** Constructor. n: input length string; module_idx: its idx in
	the entire concurrent running of jsnark circuits (starting from 0); 
	num_modules:
	total number of jsnark circuits being run concurrently.
	n is required to be a multiple of 252 for ALL modules except the last 
	one, otherwise the chaned hash will not work. */
	public ZaModularVerifierV3(ZaConfig config_in, ZaGenerator zg, 
		int N, int state_bits, int module_idx, int num_modules,
		int max_final_state_idx){
		super(config_in, "ModularTraceVerifier", zg);
		int me = module_idx;
		int np = num_modules;
		this.n = me<np-1? N/np: N/np + N%np;
		this.NT = 2*N + 1;
		this.NS = 2*N + 1 + np;
		this.nt = me<np-1? NT/np: NT/np + NT%np;
		this.ns = me<np-1? NS/np: NS/np + NS%np;
		if(me<np-1 && n%63!=0){ //63 4-bit nibbles
			Utils.fail("CHUNK input length: " + n + " required to be multiple of 252/4 for the module");
		}	

		this.module_idx = module_idx;
		this.num_modules = num_modules;
		this.N = N;
		this.max_final_state_idx = max_final_state_idx;
		this.state_bits = state_bits;
		this.arrStates = new Wire [2*n+1];
		this.arrInput = new Wire[2*n];
		this.arrBFail= new Wire[2*n];
		this.arrAlignedInput= new Wire[n];

		this.S_P = new Wire [ns];
		this.S_GCD = new Wire [ns];
		this.S_P_GCD = new Wire [ns];
		this.S_PD_GCD = new Wire [ns];
		this.S_S = new Wire [ns];
		this.S_T = new Wire [ns];
		this.T_P = new Wire [nt];
		this.T_GCD = new Wire [nt];
		this.T_P_GCD = new Wire [nt];
		this.T_PD_GCD = new Wire [nt];
		this.T_S = new Wire [nt];
		this.T_T = new Wire [nt];

		this.arrStates_logical = new BigInteger [2*n+1];
		this.arrInput_logical = new BigInteger[2*n];
		this.arrBFail_logical = new BigInteger[2*n];
		this.arrAlignedInput_logical = new BigInteger[n];

		this.S_P_logical = new BigInteger [ns];
		this.S_GCD_logical = new BigInteger [ns];
		this.S_P_GCD_logical = new BigInteger [ns];
		this.S_PD_GCD_logical = new BigInteger [ns];
		this.S_S_logical = new BigInteger [ns];
		this.S_T_logical = new BigInteger [ns];
		this.T_P_logical = new BigInteger [nt];
		this.T_GCD_logical = new BigInteger [nt];
		this.T_P_GCD_logical = new BigInteger [nt];
		this.T_PD_GCD_logical = new BigInteger [nt];
		this.T_S_logical = new BigInteger [nt];
		this.T_T_logical = new BigInteger [nt];
	}

	/** returns 1. 
	All input in witness. The only input is wire r (random challenge)
	and its inverse r_inv. */
	public int getNumPublicInputs(){
		return 2;
	}

	/** the length of all witness inputs.  */
	public int getNumWitnessInputs(){
		int expected_len = 7*n + 38 + 6*ns + 6*nt;
		return expected_len;
	}

	/** no public output wires for all modules except the last module. 
	The "output" are still secret witness wires
	The last module outputs 2 lines: (1) O = z+S_P_GCD(r) * S_T_GCD(r) 
	where S_P_GCD and s_T_GCD are the set support of 
		states and transitions; (2) hash_out
	*/
	public int getNumOutputs(){ 
		return this.module_idx<this.num_modules-1? 0: 2;
	}

	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - arrStates, arrInput, arrBFail, arrAlignedInput
		all aligned.
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		this.logical_setup_witness(arrWitness);
		this.r_logical = arrPubInput[0];
		this.r_inv_logical = arrPubInput[1];
	
		//0. check the input
		logical_assert_r_inv(arrPubInput[0], arrPubInput[1]);
		
		//1. check all boolean
		logical_assert_boolean(this.arrBFail_logical);

		//2. check fail edges
		logical_assert_valid_fail_edges(this.arrBFail_logical, this.arrInput_logical);
		//3. check aligned input is input
		logical_assert_valid_aligned(this.arrInput_logical, this.arrAlignedInput_logical, this.arrBFail_logical, this.r_logical);

		//4. build output (secret witness) and verify validity
		// pass this object's data members as params
		logical_assert_chunk_polys(
			n, ns, nt,  
			arrStates_logical, r_logical,  arrInput_logical,  arrBFail_logical,  arrAlignedInput_logical,  
			S_P_logical,  S_GCD_logical,  S_P_GCD_logical,  S_PD_GCD_logical,  S_S_logical,  S_T_logical,  
			T_P_logical,  T_GCD_logical,  T_P_GCD_logical,  T_PD_GCD_logical,  T_S_logical,  T_T_logical, 
			hash_in_logical, v_s_p_in_logical, v_s_pd_in_logical, v_s_gcd_in_logical, v_s_p_gcd_in_logical, v_s_pd_gcd_in_logical, v_s_s_in_logical, v_s_t_in_logical, 
			v_t_p_in_logical, v_t_pd_in_logical, v_t_gcd_in_logical, v_t_p_gcd_in_logical, v_t_pd_gcd_in_logical, v_t_s_in_logical, v_t_t_in_logical, 
			hash_out_logical, v_s_p_logical, v_s_pd_logical, v_s_gcd_logical, v_s_p_gcd_logical, v_s_pd_gcd_logical, v_s_s_logical, v_s_t_logical, 
			v_t_p_logical, v_t_pd_logical, v_t_gcd_logical, v_t_p_gcd_logical, v_t_pd_gcd_logical, v_t_s_logical, v_t_t_logical
		);

		//5. if the last module DOUBLE CHECK
		if(this.module_idx==this.num_modules-1){
			logical_assert_set_support("State", v_s_p_logical, v_s_pd_logical, v_s_gcd_logical, v_s_p_gcd_logical, v_s_pd_gcd_logical, v_s_s_logical, v_s_t_logical);
			logical_assert_set_support("Transitions", v_t_p_logical, v_t_pd_logical, v_t_gcd_logical, v_t_p_gcd_logical, v_t_pd_gcd_logical, v_t_s_logical, v_t_t_logical);
		}

		//7. return output lines
		if(this.module_idx<this.num_modules-1){
			return new BigInteger [] {};
		}else{
			BigInteger modulus = this.config.getFieldOrder();
			BigInteger zp = this.z_logical.add(this.v_s_p_gcd_logical.multiply(this.v_t_p_gcd_logical)).mod(modulus); 
			return new BigInteger [] {zp, this.hash_out_logical};
		}
	}


	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		arrWitness - arrStates, arrInput, arrBFail, arrAlignedInput
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		this.w_zero = this.generator.createConstantWire(0);
		this.w_one= this.generator.createConstantWire(1);
		this.setup_witness(arrWitness);
		this.r= arrPubInput[0];
		this.r_inv= arrPubInput[1];

		//0. check the input
		assert_r_inv(arrPubInput[0], arrPubInput[1]);

		//1. check all boolean
		assert_boolean(this.arrBFail);

		//2. check fail edges
		assert_valid_fail_edges(this.arrBFail, this.arrInput);

		//3. check aligned input is input
		assert_valid_aligned(this.arrInput, this.arrAlignedInput, this.arrBFail, this.r);

		//4. build output (secret witness) and verify validity
		// pass this object's data members as params
		assert_chunk_polys(n, ns, nt,  
			arrStates, r,  arrInput,  arrBFail,  arrAlignedInput,  
			S_P,  S_GCD,  S_P_GCD,  S_PD_GCD,  S_S,  S_T,  
			T_P,  T_GCD,  T_P_GCD,  T_PD_GCD,  T_S,  T_T, 
			hash_in, v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, v_s_s_in, v_s_t_in, 
			v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, v_t_s_in, v_t_t_in, 
			hash_out, v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, v_s_s, v_s_t, 
			v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, v_t_s, v_t_t
		);

		//6. if the last module DOUBLE CHECK
		if(this.module_idx==this.num_modules-1){
			assert_set_support("State", v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, v_s_s, v_s_t);
			assert_set_support("Transitions", v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, v_t_s, v_t_t);
		}

		//7. return output lines
		if(this.module_idx<this.num_modules-1){
			return new Wire [] {};
		}else{
			Wire zp = this.z.add(this.v_s_p_gcd.mul(this.v_t_p_gcd)); 
			return new Wire [] {zp, this.hash_out};
		}
	}

	
	/** Generate the random inputs. Mainly rely on dizkDriver */
	public BigInteger[][] genRandomInput(int seed_n){
		// WRONG IMPLEMENTATION should never call
		throw new RuntimeException("ZaModularVerifierV3V3's genRandomInput should never be called!");
	}
}
