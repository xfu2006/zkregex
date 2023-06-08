/* ***************************************************
Dr. CorrAuthor
@Copyright 2022
Created: 03/27/2022
Modified: 06/15/2022
Further modified: 07/07/2022 (add more inputs - set support part)
* ***************************************************/

/** **************************************************
This is a verifier for a given automaton trace
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
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.hash.poseidon.*;
import util.Util;
import cs.Employer.ac.AC; 
import cs.Employer.zkregex.App;

/** **************************************************
This is a verifier for a valid trace of running a string over an automaton.
Input:
	arrStates: array of states
	arrInput: the sequence of input characters. arrStates and arrInput
are almost always paired, with the exception that arrStates has one more
state. The sequence may be padded with Fail edges if the input shorter
than the circuit capacity. 
	arrBFail: whether the corresponding input (transition) should be regarded
as a fail edge in Aho-Corasic DFA. If the flag is set to true, then
the corresponding character should be IGNORED in building the hash.
	arrAlignedInput: the compacted input keeping the original order
but with the characters on Fail Edges removed (ALWAYS make sure that
we don't need to pad it).
	r: the random nonce for evaluating state polynomials S
	r_2: a second random nonce of r2*S(r)
	r_3: random nonce for evaluating polynomial for transition T
	r_4: random nonce for outputing r4*T(r_3)
	---- Set support part ---- 
	---- (also check main/.../acc_driver/AccDriver for definitions) ---
	---- each array will be |arrStates|+1 ---
	S_P: polynoail for states representing states
	S_GCD: GCD of S_P and S_PD (derivative)
	S_P_GCD: P-GCD
	S_PD_GCD: Derivative of P - GCD. NOTE! we will use circ to calculate
		derivative (S_PD) from S_P, instead of asking prover to provide
		it as a witness. (see function get_derivative(...))
	S_S: Bizout coefs for proviing S__P_GCD and S_PD_GCD are disjoint
	S_T: 2nd Bizout coefs
	T_P: the following are the poly version for the sets of transitions
	T_GCD
	T_P_GCD
	T_PD_GCD
	T_S 
	T_T
	T_TS: Biztou coefs for showing set of states and transitions are disjoint 
	S_TS:
	


Output:
	p_acc_states: evaluating the bilinear accumulator polynomial for
all states in arrStates. The polynomial is defined as
	(r+s1)(r+s2) ... (r+sn)
	The output is blinded by: p_acc_states(r) * r2
	p_acc_transitions: evaluating the polynomial for transitions.
		The actual output is: p_acc_transition(r3)*r4
	hash: the hash of all input characters in arrAlignedInput.
Note: if the input is less than the circuit size, padd it with 0.
	Later these two values will be combined with polynomial bilinear
related protocols to prove the validity of the trace.

* ***************************************************/
public class ZaTraceVerifier extends ZaCirc{
	/** The size of REAL input string length (excluding fail edges). n has to be a MULTIPLE of 256 */
	protected int n;
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
	/** random nonce supplied by verifier */
	protected Wire r;
	/** output line: polynomial eval of acc for states */
	protected Wire p_acc_states;
	/** output line: polynomial eval of acc for transitions */
	protected Wire p_acc_transitions;
	/** output line: the hash of arrAlignedInput */
	protected Wire hash;
	/** randon nonce input for p_acc_states */
	protected Wire r1;
	/** blinding factor for p_acc_states(r1) */
	protected Wire r2;
	/** random input for p_acc_transitions */
	protected Wire r3;
	/** blinding factor for p_acc_trans(r3) */
	protected Wire r4;
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

	/** Bizout coef1 for proving S_P_GCD and T_P_GCD disjoint */
	protected Wire [] S_TS;
	/** Bizout coef2 for proving S_P_GCD and T_P_GCD disjoint */
	protected Wire [] T_TS;

	// --- The following are for logical evaluation --
	/** for logical eval, corresponding to arrStates*/
	protected BigInteger[] arrStates_logical;
	/** for logical eval, corresponding to arrInput */
	protected BigInteger [] arrInput_logical;
	/** for logical evla, corresponding to arrBFail */
	protected BigInteger [] arrBFail_logical;
	/** for logical eval, corresponding to arrAlignedInput */
	protected BigInteger [] arrAlignedInput_logical;
	/** random nonce supplied by verifier, logical */
	protected BigInteger r_logical;
	protected BigInteger r1_logical;
	protected BigInteger r2_logical;
	protected BigInteger r3_logical;
	protected BigInteger r4_logical;

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

	/** Bizout coef1 for proving S_P_GCD and T_P_GCD disjoint */
	protected BigInteger [] S_TS_logical;
	/** Bizout coef2 for proving S_P_GCD and T_P_GCD disjoint */
	protected BigInteger [] T_TS_logical;

	/** output line: polynomial eval of acc for states */
	protected BigInteger p_acc_states_logical;
	/** output line: polynomial eval of acc for transitions */
	protected BigInteger p_acc_transitions_logical;
	/** output line: the hash of arrAlignedInput */
	protected BigInteger hash_logical;

	protected Wire w_zero; //zero constant wire
	protected Wire w_one; //one constant wire


	// *** Operations ***
	/** NOTE: setPriceServer has to be called later */
	public ZaTraceVerifier(ZaConfig config_in, ZaGenerator zg, int n, int state_bits){
		super(config_in, "TraceVerifier", zg);
		this.n = n;
		this.state_bits = state_bits;
		this.arrStates = new Wire [2*n+1];
		this.arrInput = new Wire[2*n];
		this.arrBFail= new Wire[2*n];
		this.arrAlignedInput= new Wire[n];

		this.S_P = new Wire [2*n+2];
		this.S_GCD = new Wire [2*n+2];
		this.S_P_GCD = new Wire [2*n+2];
		this.S_PD_GCD = new Wire [2*n+2];
		this.S_S = new Wire [2*n+2];
		this.S_T = new Wire [2*n+2];
		this.T_P = new Wire [2*n+2];
		this.T_GCD = new Wire [2*n+2];
		this.T_P_GCD = new Wire [2*n+2];
		this.T_PD_GCD = new Wire [2*n+2];
		this.T_S = new Wire [2*n+2];
		this.T_T = new Wire [2*n+2];
		this.S_TS = new Wire [2*n+2];
		this.T_TS = new Wire [2*n+2];


		this.arrStates_logical = new BigInteger [2*n+1];
		this.arrInput_logical = new BigInteger[2*n];
		this.arrBFail_logical = new BigInteger[2*n];
		this.arrAlignedInput_logical = new BigInteger[n];

		this.S_P_logical = new BigInteger [2*n+2];
		this.S_GCD_logical = new BigInteger [2*n+2];
		this.S_P_GCD_logical = new BigInteger [2*n+2];
		this.S_PD_GCD_logical = new BigInteger [2*n+2];
		this.S_S_logical = new BigInteger [2*n+2];
		this.S_T_logical = new BigInteger [2*n+2];
		this.T_P_logical = new BigInteger [2*n+2];
		this.T_GCD_logical = new BigInteger [2*n+2];
		this.T_P_GCD_logical = new BigInteger [2*n+2];
		this.T_PD_GCD_logical = new BigInteger [2*n+2];
		this.T_S_logical = new BigInteger [2*n+2];
		this.T_T_logical = new BigInteger [2*n+2];
		this.S_TS_logical = new BigInteger [2*n+2];
		this.T_TS_logical = new BigInteger [2*n+2];
	}

	/** set up the witness from arrInput. 
	Assumption: arrInput layed out as:
		arrStates (2n+1), arrInput (2n), arrBFail (2n), arrAlignedInput(n), r, r1, r2, r3, r4.  Now: 7n+6 elements
		Then the following 14 arrays are each of 2n+2 elements
		S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T
		T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T,
		S_TS, T_TS. (28n + 28) elements
	Total: 35n + 34 elements
	*/	
	protected void setup_witness(Wire [] arrIn){
		//1. get the first part
		if(arrIn.length!=35*n+34){
			Utils.fail("arrIn.len!=35n+34. len: " + arrIn.length + ", n: " + n);
		}
		int [] arrLen = new int [] {2*n+1, 2*n, 2*n, n};
		Wire [][] arr2d = new Wire[][] {arrStates, this.arrInput, arrBFail, 
			arrAlignedInput};
		int idx = 0;
		for(int i=0; i<arr2d.length; i++){
			int len = arrLen[i];
			Wire [] target = arr2d[i];
			for(int j=0; j<len; j++){
				target[j] = arrIn[idx];
				idx++;
			}
		}
		this.r= arrIn[idx];
		this.r1= arrIn[idx+1];
		this.r2= arrIn[idx+2];
		this.r3= arrIn[idx+3];
		this.r4= arrIn[idx+4];

		//2. get the 2nd part (14 arrays)
		int cur_idx = 7*n + 6;
		if(idx+5!=cur_idx){  
			Utils.fail("cur_idx!=7n+6. cur_idx: " + cur_idx + ", n: " + n);
		}
		Wire [][] arr2cp = new Wire [][] {
			S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T,
			T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T,
			S_TS, T_TS
		};
		for(int i=0; i<arr2cp.length; i++){
			int len = 2*n + 2;
			for(int j=0; j<len; j++){
				arr2cp[i][j] = arrIn[cur_idx + i*(2*n+2) + j];
			}
		}
	}

	/** set up the witness from arrInput logically. 
	Assumption: arrInput layed out as:
		arrStates (2n+1), arrInput (2n), arrBFail (2n), arrAlignedInput(n),
		r1, r2, r3, r4.
		Then the following 14 arrays are each of 2n+2 elements
		S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T
		T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T,
		S_TS, T_TS. (28n + 28) elements
	Total: 35n + 34 elements
	*/	
	protected void logical_setup_witness(BigInteger [] arrInput){
		if(arrInput.length!=35*n+34){
			Utils.fail("arrInput.length() != 35*n+34. len: " +
				arrInput.length + ", n: " + n);
		}
		int [] arrLen = new int [] {2*n+1, 2*n, 2*n, n};
		BigInteger [][] arr2d = new BigInteger[][] 
			{arrStates_logical, arrInput_logical, 
				arrBFail_logical, arrAlignedInput_logical};
		int idx = 0;
		for(int i=0; i<arr2d.length; i++){
			int len = arrLen[i];
			BigInteger [] target = arr2d[i];
			for(int j=0; j<len; j++){
				target[j] = arrInput[idx];
				idx++;
			}
		}
		this.r_logical = arrInput[idx];
		this.r1_logical = arrInput[idx+1];
		this.r2_logical = arrInput[idx+2];
		this.r3_logical = arrInput[idx+3];
		this.r4_logical = arrInput[idx+4];

		//2. get the 2nd part (14 arrays)
		int cur_idx = 7*n + 6;
		if(idx+5!=cur_idx){  
			Utils.fail("cur_idx!=7n+6. cur_idx: " + cur_idx + ", n: " + n);
		}
		BigInteger [][] arr2cp = new BigInteger [][] {
			S_P_logical, S_GCD_logical, S_P_GCD_logical, S_PD_GCD_logical, S_S_logical, S_T_logical,
			T_P_logical, T_GCD_logical, T_P_GCD_logical, T_PD_GCD_logical, T_S_logical, T_T_logical,
			S_TS_logical, T_TS_logical
		};
		for(int i=0; i<arr2cp.length; i++){
			int len = 2*n + 2;
			for(int j=0; j<len; j++){
				arr2cp[i][j] = arrInput[cur_idx + i*(2*n+2) + j];
			}
		}
	}


	/** returns 0. All input in witness */
	public int getNumPublicInputs(){
		return 0;
	}

	/** the length of all witness inputs. It will be
		2n+1 + 2n + 2n  + n + 5 = 7n + 6
		2nd part of witness: 28n+28 (14 arrays of 2n+2 each)
		Total: 35n + 34
	*/
	public int getNumWitnessInputs(){
		return 35*n + 34;
	}

	/** 3 output lines: p_acc_states, p_acc_transitions, hash
	*/	
	public int getNumOutputs(){ 
		return 3;
	}

	/** produce the value of:
		(r+a[0])...(r+a[n]) * r2
		This the clear-text (exponent) part of Ngyen's bilinear accumulator
		Assumption: a.length>1
	*/
	protected Wire build_bin_acc(Wire [] a, Wire r, Wire r2){
		Wire res = a[0].add(r);
		for(int i=1; i<a.length; i++){
			res = res.mul(a[i].add(r));
		} 	
		return res.mul(r2);
	}

	/** logical version of build_bin_acc */
	protected BigInteger logical_build_bin_acc(BigInteger [] a, BigInteger r, BigInteger r2){
		BigInteger modulus = this.config.getFieldOrder();
		for(int i=0; i<a.length; i++){
		}
		BigInteger res = a[0].add(r);
		for(int i=1; i<a.length; i++){
			res = res.multiply(a[i].add(r)).mod(modulus);
		} 	
		return res.multiply(r2).mod(modulus);
	}

	/** treat a as a coef vector of polynomial
		p(x) = a[0] + a[1]*x + a[2]*x^2 + ... a[n-1]*x^{n-1}
		evaluate and return p(r)
	*/
	protected Wire eval_poly(Wire [] a, Wire r){
		int n = a.length-1;
		Wire res = a[n];
		for(int i=1; i<a.length; i++){
			res = res.mul(r).add(a[n-i]);
		} 	
		return res;
	}

	/** logical version of eval_poly */
	protected BigInteger logical_eval_poly(BigInteger [] a, BigInteger r){
		int n = a.length-1;
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger res = a[n];
		for(int i=1; i<a.length; i++){
			res = res.multiply(r).add(a[n-i]).mod(modulus);
		} 	
		return res;
	}

	/** Let a be the coefs vector (a[0] is the coef for degree 0).
	return the coefs vector (same size) of the derivative.
	E.g., a = [1, 2, 3] is the coefs for p(x) = 3x^2 + 2x + 1.
	Its derivative is p'(x) = 6x + 2.
	Thus the return would be [2, 6, 0]
	*/
	protected Wire [] get_derivative(Wire [] a){
		int n = a.length;
		Wire [] b = new Wire [n];
		b[n-1] = this.generator.createConstantWire(0);
		for(int i=0; i<n-1; i++){
			Wire factor = this.generator.createConstantWire(i+1);
			b[i] = a[i+1].mul(factor);
		}
		return b;
	}

	/** logical version of get_derivative */
	protected BigInteger [] logical_get_derivative(BigInteger [] a){
		int n = a.length;
		BigInteger [] b = new BigInteger [n];
		b[n-1] = Utils.itobi(0);
		for(int i=0; i<n-1; i++){
			BigInteger factor = Utils.itobi(i+1);
			b[i] = a[i+1].multiply(factor);
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
		int bits2 = this.state_bits*2 + 1;
		int bits1 = this.state_bits + 1;
		for(int i=0; i<n; i++){
			trans[i] = bFail[i].add(
				states[i+1].multiply(two).add(
					chars[i].multiply(pow2).add(
						states[i].multiply(pow1)
					)
				)
			).add(pow62);
			/* ALTERNATIVE. but not much more helpful
			trans[i]= bFail[i].add(
				states[i+1].shiftLeft(1).add(
					chars[i].shiftLeft(bits2).add(
						states[i].shiftLeft(bits1)
					)
				)
			).add(pow62);
			*/
		}
		return trans;
	}


	/** Given a[] is an array of 4-bit numbers, build
		an array of 252-bit numbers (to accompodate bn254). 
		The size of the returned array is ceil(a.length/64). 
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
	protected Wire build_hash(Wire [] arrAlignedInput){
		//1. pack every 64 elements of arrAlignedInput as a 252-bit number
		Wire [] arr252bits = build_252bit(arrAlignedInput);

		//2. hash the arr252bitInt 
		ZaHash2 hash = new ZaPoseidon(config, (ZaGenerator) this.generator);
		if(arr252bits.length>1){
        	hash.build_circuit(new Wire [] {}, 
				new Wire [] {arr252bits[0], arr252bits[1]});
		}else{
        	hash.build_circuit(new Wire [] {}, 
				new Wire [] {arr252bits[0], arr252bits[0]});
		}
        Wire res = hash.getOutputWires()[0];
		for(int i=2; i<arr252bits.length; i++){
			hash = ZaHash2.new_hash(config, (ZaGenerator) this.generator);
        	hash.build_circuit(new Wire [] {}, 
				new Wire [] {res, arr252bits[i]});
        	res = hash.getOutputWires()[0];
			
		}
		return res;
	}

	protected BigInteger logical_build_hash(BigInteger [] arrAlignedInput){
		//1. pack every 64 elements of arrAlignedInput as a 252-bit number
		BigInteger [] arr252bits = logical_build_252bit(arrAlignedInput);

		//2. hash the arr252bitInt 
		ZaHash2 hash = new ZaPoseidon(config, (ZaGenerator) this.generator);
        BigInteger res = arr252bits.length>1?
			hash.hash2(arr252bits[0], arr252bits[1]):
			hash.hash2(arr252bits[0], arr252bits[0]);
		for(int i=2; i<arr252bits.length; i++){
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
				Utils.warn("arrB[" + i + "] is not booean!");
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
				Utils.warn("logical_assert_valid_inputs fail at index " + i);
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
		BigInteger w_one = Utils.itobi(1);
		BigInteger w_zero= Utils.itobi(0);
		int n = a2.length; //asumming a1 is 2n, b is 2n
		BigInteger [] r1 = new BigInteger [2*n];
		BigInteger [] r2 = new BigInteger [2*n];
		BigInteger [] r3 = new BigInteger [2*n];
		BigInteger [] nb = new BigInteger [2*n]; //neg_b
		r1[0] = w_one;
		r2[0] = w_one;
		r3[0] = w_one;

		for(int i=0; i<2*n; i++){
			nb[i] = w_one.subtract(b[i]);
		}
		for(int i=1; i<2*n; i++){
			r2[i] = r2[i-1].multiply(r);
			r3[i] = r3[i-1].multiply(nb[i]).multiply(r).add(
				b[i].multiply(r3[i-1]) );
			r1[i] = r3[i].multiply(nb[i]);
		}

		BigInteger p1 = w_one;
		BigInteger p2 = w_one;
		for(int i=0; i<2*n; i++){
			p1 = p1.add(a1[i].multiply(r1[i]));
		}
		for(int i=0; i<n; i++){
			p2 = p2.add(a2[i].multiply(r2[i]));
		}
		if(!p1.equals(p2)){
			Utils.warn("assert_valid_aligned");
		}
	}

	/** assert that v1 = v2 */
	private void logical_addEqualityAssertion(BigInteger v1, BigInteger v2, String msg){
		if(!v1.equals(v2)){
			System.out.println("v1: " + v1 + ", v2: "  + v2);
			Utils.fail("ERROR: " + msg);
		}
	}
	/** assert that the witness of set support are correct
	for both the multi-sets of states and transitions.
	NOTE: to save the cost of calculating polynoimal values,
	we do not refactor this function (which we could have
	designed a function for proving set_support for 1 multi-set and
	call it twice).
	NOTE2: all input variables reflects the name of data members
	such as S_P. We explicitly list them here for future
	refactoring purpose.
	NOTE3: the use of two extra input v_s_p and v_t_p is to save
	to polynomial evaluations (as the are already evaluated earlier).
	*/
	public void assert_set_support(
		//1. eval polynomials
		Wire [] s_p,  Wire [] s_gcd,  Wire [] s_p_gcd, Wire [] s_pd_gcd, 
		Wire [] s_s, Wire [] s_t, 
		Wire [] t_p,  Wire [] t_gcd,  Wire [] t_p_gcd, Wire [] t_pd_gcd, 
		Wire [] t_s, Wire [] t_t, 
		Wire [] s_ts, Wire [] t_ts, Wire r,
		Wire v_s_p, Wire v_t_p){
		Wire v_s_gcd = eval_poly(s_gcd, r);
		Wire v_s_p_gcd = eval_poly(s_p_gcd, r); 
		Wire v_s_pd_gcd = eval_poly(s_pd_gcd, r); 
		Wire v_s_s = eval_poly(s_s, r); 
		Wire v_s_t = eval_poly(s_t, r);
		Wire v_t_gcd = eval_poly(t_gcd, r); 
		Wire v_t_p_gcd = eval_poly(t_p_gcd, r); 
		Wire v_t_pd_gcd = eval_poly(t_pd_gcd, r); 
		Wire v_t_s = eval_poly(t_s, r); 
		Wire v_t_t = eval_poly(t_t, r); 
		Wire v_s_ts= eval_poly(s_ts, r);
		Wire v_t_ts= eval_poly(t_ts, r);

		Wire [] s_pd = get_derivative(s_p);
		Wire v_s_pd = eval_poly(s_pd, r);
		Wire [] t_pd = get_derivative(t_p);
		Wire v_t_pd = eval_poly(t_pd, r);

		//2. check set support proof for states
		//2.1 check p_gcd UNION gcd = p (for set states)
		Wire prod_s_gcd_s_p_gcd = v_s_gcd.mul(v_s_p_gcd);
		generator.addEqualityAssertion(prod_s_gcd_s_p_gcd, v_s_p, "p_gcd * gcd !=p for states");

		//2.2 check pd_gcd UNION gcd = pd (for set states) 
		Wire prod_s_gcd_s_pd_gcd = v_s_gcd.mul(v_s_pd_gcd);
		generator.addEqualityAssertion(prod_s_gcd_s_pd_gcd, v_s_pd, "(pd-gcd) * gcd !=pd for states");

		//2.3 check p_gcd and pd_gcd are disjoint
		Wire one = generator.createConstantWire(1);
		Wire bizout_p_gcd_pd_gcd = v_s_p_gcd.mul(v_s_s).add(
			v_s_pd_gcd.mul(v_s_t)
		);
		generator.addEqualityAssertion(bizout_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for states");

		//3. check set support proof for transitions 
		//3.1 check p_gcd UNION gcd = p (for transitions)
		Wire prod_t_gcd_t_p_gcd = v_t_gcd.mul(v_t_p_gcd);
		generator.addEqualityAssertion(prod_t_gcd_t_p_gcd, v_t_p, "p_gcd * gcd !=p for transitions");

		//3.2 check pd_gcd UNION gcd = pd (for transitions) 
		Wire prod_t_gcd_t_pd_gcd = v_t_gcd.mul(v_t_pd_gcd);
		generator.addEqualityAssertion(prod_t_gcd_t_pd_gcd, v_t_pd, "(pd-gcd) * gcd !=pd for transitions");

		//3.3 check p_gcd and pd_gcd are disjoint
		Wire bizout_t_p_gcd_pd_gcd = v_t_p_gcd.mul(v_t_s).add(
			v_t_pd_gcd.mul(v_t_t)
		);
		generator.addEqualityAssertion(bizout_t_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for transitions");

		//4. check set support of states and of transitions disjoint
		//Here: set_support of states: s_p_gcd 
		//		set_support of stransitions: t_p_gcd
		// two Bizout coefs: s_ts and t_ts 
		Wire bizout_s_t = v_s_p_gcd.mul(v_s_ts).add(
			v_t_p_gcd.mul(v_t_ts)
		);
		generator.addEqualityAssertion(bizout_s_t, one, "set_states union set_transitions !=emptyset");
	}

	/** logical version of assert_set_support */
	public void logical_assert_set_support(
		BigInteger [] s_p,  BigInteger [] s_gcd,  BigInteger [] s_p_gcd, 
		BigInteger [] s_pd_gcd, 
		BigInteger [] s_s, BigInteger [] s_t, 
		BigInteger [] t_p,  BigInteger [] t_gcd,  
		BigInteger [] t_p_gcd, BigInteger [] t_pd_gcd, 
		BigInteger [] t_s, BigInteger [] t_t, 
		BigInteger [] s_ts, BigInteger [] t_ts, BigInteger r,
		BigInteger v_s_p, BigInteger v_t_p){

		//0. get the modulus
		BigInteger modulus = this.config.getFieldOrder();
		//1. eval polynomials
		BigInteger v_s_gcd = logical_eval_poly(s_gcd, r);
		BigInteger v_s_p_gcd = logical_eval_poly(s_p_gcd, r); 
		BigInteger v_s_pd_gcd = logical_eval_poly(s_pd_gcd, r); 
		BigInteger v_s_s = logical_eval_poly(s_s, r); 
		BigInteger v_s_t = logical_eval_poly(s_t, r);
		BigInteger v_t_gcd = logical_eval_poly(t_gcd, r); 
		BigInteger v_t_p_gcd = logical_eval_poly(t_p_gcd, r); 
		BigInteger v_t_pd_gcd = logical_eval_poly(t_pd_gcd, r); 
		BigInteger v_t_s = logical_eval_poly(t_s, r); 
		BigInteger v_t_t = logical_eval_poly(t_t, r); 
		BigInteger v_s_ts= logical_eval_poly(s_ts, r);
		BigInteger v_t_ts= logical_eval_poly(t_ts, r);

		BigInteger [] s_pd = logical_get_derivative(s_p);
		BigInteger v_s_pd = logical_eval_poly(s_pd, r);
		BigInteger [] t_pd = logical_get_derivative(t_p);
		BigInteger v_t_pd = logical_eval_poly(t_pd, r);

		//2. assert the set proof for states
		//2.1 check p_gcd UNION gcd = p (for set states)
		BigInteger prod_s_gcd_s_p_gcd = v_s_gcd.multiply(v_s_p_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_s_gcd_s_p_gcd, v_s_p, "(p-gcd) * gcd !=p for states");
		//2.2 check pd_gcd UNION gcd = pd (for set states) 
		BigInteger prod_s_gcd_s_pd_gcd = v_s_gcd.multiply(v_s_pd_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_s_gcd_s_pd_gcd, v_s_pd, "(pd-gcd) * gcd !=pd for states");

		//2.3 check p_gcd and pd_gcd are disjoint (for set states);
		BigInteger one = Utils.itobi(1);
		BigInteger bizout_p_gcd_pd_gcd = v_s_p_gcd.multiply(v_s_s).add(
			v_s_pd_gcd.multiply(v_s_t)
		).mod(modulus);
		logical_addEqualityAssertion(bizout_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for states");
		
		//3. assert the set proof for transitions 
		//3.1 check p_gcd UNION gcd = p (for transitions)
		BigInteger prod_t_gcd_t_p_gcd = v_t_gcd.multiply(v_t_p_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_t_gcd_t_p_gcd, v_t_p, "(p-gcd) * gcd !=p for transitions");

		//3.2 check pd_gcd UNION gcd = pd (for transitions) 
		BigInteger prod_t_gcd_t_pd_gcd = v_t_gcd.multiply(v_t_pd_gcd).mod(modulus);
		logical_addEqualityAssertion(prod_t_gcd_t_pd_gcd, v_t_pd, "(pd-gcd) * gcd !=pd for transitions");

		//3.3 check p_gcd and pd_gcd are disjoint (for set states);
		BigInteger bizout_t_p_gcd_pd_gcd = v_t_p_gcd.multiply(v_t_s).add(
			v_t_pd_gcd.multiply(v_t_t)
		).mod(modulus);
		logical_addEqualityAssertion(bizout_t_p_gcd_pd_gcd, one, "(pd-gcd) intersect (p-gcd) !=emptyset for transitions");

		//4. check set support of states and of transitions disjoint
		//Here: set_support of states: s_p_gcd 
		//		set_support of stransitions: t_p_gcd
		// two Bizout coefs: s_ts and t_ts 
		BigInteger bizout_s_t = v_s_p_gcd.multiply(v_s_ts).add(
			v_t_p_gcd.multiply(v_t_ts)
		).mod(modulus);
		logical_addEqualityAssertion(bizout_s_t, one, "set_states union set_transitions !=emptyset");
	}



	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - arrStates, arrInput, arrBFail, arrAlignedInput
		all aligned.
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		this.logical_setup_witness(arrWitness);
		
		//1. check all boolean
		logical_assert_boolean(this.arrBFail_logical);

		//2. check fail edges
		logical_assert_valid_fail_edges(this.arrBFail_logical, this.arrInput_logical);
		//3. check aligned input is input
		logical_assert_valid_aligned(this.arrInput_logical, this.arrAlignedInput_logical, this.arrBFail_logical, this.r_logical);

		//4. build output
		this.p_acc_states_logical= logical_build_bin_acc(this.arrStates_logical, this.r1_logical, this.r2_logical);
		this.p_acc_transitions_logical= logical_build_bin_acc(logical_build_trans(this.arrStates_logical, this.arrInput_logical, this.arrBFail_logical), this.r1_logical, this.r2_logical);
		this.hash_logical = logical_build_hash(this.arrAlignedInput_logical);

		//---- EXTRA CHECK OF SET-SUPPORT
		//1. check consistency of S_P and arrStates (also T_P and arrTrans)
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger v_S_P1 = logical_eval_poly(
			this.S_P_logical, this.r1_logical).mod(modulus);
		BigInteger v_S_P = v_S_P1.multiply(this.r2_logical).
			mod(modulus);
		if(!v_S_P.equals(p_acc_states_logical)){
			System.out.println("DEBUG USE 999 *** p_acc_states: " + p_acc_states_logical + ", v_S_P: " + v_S_P);
			Utils.fail( "State Polynomial Consistency Fails");
		}
		BigInteger v_T_P1 = logical_eval_poly(
			this.T_P_logical, this.r1_logical).mod(modulus);
		BigInteger v_T_P = v_T_P1.multiply(this.r2_logical).
			mod(modulus);
		if(!v_T_P.equals(p_acc_transitions_logical)){
			System.out.println("DEBUG USE 999 *** p_acc_transitions: " + p_acc_transitions_logical + ", v_T_P: " + v_T_P);
			Utils.fail( "Transition Polynomial Consistency Fails");
		}

		//2. check set support proof
		logical_assert_set_support(
			this.S_P_logical, this.S_GCD_logical, 
				this.S_P_GCD_logical, this.S_PD_GCD_logical, 
				this.S_S_logical, this.S_T_logical,
			this.T_P_logical, this.T_GCD_logical, 
				this.T_P_GCD_logical, this.T_PD_GCD_logical, 
				this.T_S_logical, this.T_T_logical,	
			this.S_TS_logical, this.T_TS_logical, this.r1_logical,
				v_S_P1, v_T_P1);
		

		return new BigInteger [] {p_acc_states_logical, p_acc_transitions_logical, hash_logical};
	}

	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		arrWitness - arrStates, arrInput, arrBFail, arrAlignedInput
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		this.setup_witness(arrWitness);
		this.w_zero = this.generator.createConstantWire(0);
		this.w_one= this.generator.createConstantWire(1);

		//1. check all boolean
		assert_boolean(this.arrBFail);

		//2. assert valid BFail leads to fail edges
		assert_valid_fail_edges(this.arrBFail, this.arrInput);

		//3. assert valid aligned array
		assert_valid_aligned(this.arrInput, this.arrAlignedInput, this.arrBFail, this.r);

		//4. build output
		this.p_acc_states= build_bin_acc(this.arrStates, this.r1, this.r2);
		this.p_acc_transitions= build_bin_acc(this.build_trans(this.arrStates, this.arrInput, this.arrBFail), this.r1, this.r2);
		this.hash = build_hash(this.arrAlignedInput);

		//---- EXTRA CHECK OF SET-SUPPORT
		//1. check consistency of S_P and arrStates (also T_P and arrTrans)
		Wire v_S_P1 = eval_poly(this.S_P, this.r1);
		Wire v_S_P = v_S_P1.mul(this.r2);
		this.generator.addEqualityAssertion(v_S_P, p_acc_states, "State Polynomial Consistency Fails");
		Wire v_T_P1 = eval_poly(this.T_P, this.r1);
		Wire v_T_P = v_T_P1.mul(this.r2);
		this.generator.addEqualityAssertion(v_T_P, p_acc_transitions, "Transition Polynomial Consistency Fails");

		//2. check the set_support proof
		assert_set_support(
			this.S_P, this.S_GCD, this.S_P_GCD, this.S_PD_GCD, 
				this.S_S, this.S_T,
			this.T_P, this.T_GCD, this.T_P_GCD, this.T_PD_GCD, 
				this.T_S, this.T_T,	
			this.S_TS, this.T_TS, this.r1,
			v_S_P1, v_T_P1);
		


		return new Wire [] {p_acc_states, p_acc_transitions, hash};
	}


/*	
	private BigInteger[][] genRandomInput_to_del(int seed_n){
		Random rand = new Random(seed_n);
		int STATES = 1024*1024; //number of states in automata
		int n = this.n; //number of real (alignedInput) chars
		BigInteger zero = Utils.itobi(0);
		BigInteger one = Utils.itobi(1);
		BigInteger [] arrBFail = new BigInteger [2*n];
		BigInteger [] arrStates = new BigInteger [2*n+1];
		BigInteger [] arrInput= new BigInteger [2*n];
		BigInteger [] arrAlignedInput = new BigInteger [n];

		//1. generate the arrBFail
		int failCount = 0; //has to be less than n
		for(int i=0; i<2*n; i++) {
			BigInteger val = BigInteger.valueOf(rand.nextInt(2));
			if(val.equals(one)) failCount++;
			arrBFail[i] =  failCount<n? val: zero;
		}
		arrBFail[0] = Utils.itobi(0); //1st edge is always non fail

		//2. generate the states, arrInputAligned, arrInputs
		arrStates[0] = Utils.itobi(0);
		int idx= 0; //the NEXT state to set
		for(int i=0; i<n; i++){
			arrAlignedInput[i] = Utils.itobi(rand.nextInt(16));
			arrInput[idx] = arrAlignedInput[i];
			arrStates[idx+1] = Utils.itobi(rand.nextInt(STATES));
			idx++;
			//2.1 copy from previous transition if the previous fail flag is 1
			for(; idx<2*n && arrBFail[idx-1].equals(one); idx++){
				arrInput[idx] = arrAlignedInput[i];
				arrStates[idx+1] = Utils.itobi(rand.nextInt(STATES));
			}
		}
		for(; idx<2*n; idx++){
				arrInput[idx] = arrAlignedInput[n-1];
				arrStates[idx] = Utils.itobi(rand.nextInt(STATES));
				arrBFail[idx] = Utils.itobi(1);
		}
		arrStates[2*n] = Utils.itobi(rand.nextInt(STATES));	

		ArrayList<BigInteger> allWit = new ArrayList<BigInteger>();
		allWit.addAll(Arrays.asList(arrStates)); 	
		allWit.addAll(Arrays.asList(arrInput)); 	
		allWit.addAll(Arrays.asList(arrBFail)); 	
		allWit.addAll(Arrays.asList(arrAlignedInput)); 	

		//3. generate r, r1, r2, r3, r4
		for(int k=0; k<5; k++){ allWit.add(Utils.randbi(250));}
		BigInteger [] arrW = Utils.toArray(allWit);

		return new BigInteger [][] {
			new BigInteger [] {},
			arrW
		};
	}
*/
	
	/** Generate the random inputs. Mainly rely on dizkDriver */
	public BigInteger[][] genRandomInput(int seed_n){
		//1. generate random AC and random input
		long seed = (long) seed_n;
		AC ac = AC.rand_clamav_ac(seed, this.n);
		ArrayList<AC.Transition> alTrans = ac.rand_accept_run(seed, this.n);

		//2. call dizkDriver to generate the input
		BigInteger[][] biInp = cs.Employer.zkregex.App.gen_circ_input_bn254a(ac, alTrans);
		return biInp;
	}
}
