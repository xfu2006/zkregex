/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/21/2021
Modified: 06/24/2021, add curve related functions
* ***************************************************/

/** **************************************************
This is a common utility class for some frequently used functions
*** *************************************************/

package za_interface.za.circs.zero_audit;

import circuit.structure.Wire;
import java.math.BigInteger;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.circs.curve.*;
import za_interface.za.circs.hash.*;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.pedersen.*;

public class common{

	public common(){};

	/** check whether the arrWitness[idx] matches the given value,
		return 1 for true. */
	protected BigInteger logical_checkVal(BigInteger [] aw, 
		int idx, BigInteger val, String msg){
		BigInteger val2 = aw[idx];
		if(!val.equals(val2)){
			Utils.log(Utils.LOG1, "WARNING: at idx " 
				+ idx + " the value: " + val2 + 
				" does not match the expectec value: " + val 
				+ ". For field: " + msg);
			return Utils.itobi(0);
		}else{
			return Utils.itobi(1);
		}
	}

	/** check whether the arrWitness[idx] matches the given value,
		return 1 for true. */
	protected Wire checkVal(Wire [] aw, 
		int idx, Wire val, String msg){
		Wire val2 = aw[idx];
		Wire res = val.isEqualTo(val2);
		return res;
	}

	// returns v and print a warning if not true
	protected BigInteger logical_checkTrue(BigInteger v, String msg){
		if(!v.equals(Utils.itobi(1))){
			Utils.log(Utils.LOG1, "WARNING: " + msg + " is not true!");
		}
		return v;
	}

	// returns v and print a warning if not true
	// This function is retained just for convenience in coding
	protected Wire checkTrue(Wire v, String msg){
		return v;
	}

	/** create a new curve by using the current ZaConfig */
	public Curve newCurve(ZaConfig config){
		ZaConfig cfg2 = config.copy();
		cfg2.hash_alg = ZaConfig.EnumHashAlg.Pedersen;
		Curve curve = Curve.createCurve(cfg2); 
		return curve;
	}
	/** just a wrapper function of pointAdd of Curve */
	public BigInteger [] pointAdd(ZaConfig config, BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2){
		Curve curve = newCurve(config); 
		return curve.pointAdd(x1, y1, x2, y2);
	}

	/** just a wrapper function for pointMul */
	public BigInteger [] pointMul(ZaConfig config, BigInteger x1, BigInteger y1, BigInteger exp){
		Curve curve = newCurve(config); 
		return curve.pointMul(x1, y1, exp);
	}

	/** Extend to full point, don't handle infinity point */
	public BigInteger [] xToPoint(ZaConfig config, BigInteger x){
		Curve curve = newCurve(config); 
		BigInteger y = curve.computeYCoordinate(x);
		return new BigInteger [] {x, y};
	}


	/** generate a pedersen nonce */
	private BigInteger gen_pedersen_nonce(ZaConfig config){
		ZaConfig cfg2 = (ZaConfig) config.copy();
		cfg2.hash_alg = ZaConfig.EnumHashAlg.Pedersen;
		ZaPedersenFull pedhash=  new ZaPedersenFull(cfg2, null);
		BigInteger [][] hash_inp = pedhash.genRandomInput(0);
		BigInteger pedersen_nonce= hash_inp[1][0]; 
		return pedersen_nonce;
	}


	/** @return [pedersen_hash_x, pedersen_hash_y, nonce_used] */
	public BigInteger [] logical_pedersen(ZaConfig config, BigInteger q){
		//1. generate an appropriate nonce
		BigInteger pedersen_nonce = gen_pedersen_nonce(config);

		//2. generate the full_perdersen (x,y) coordinates
		common cm = new common();
		ZaPedersenFull pedhash = new ZaPedersenFull(config, null);
		BigInteger [] cmt = pedhash.logical_eval(new BigInteger[]{}, 
			new BigInteger[] {pedersen_nonce, q});
		return new BigInteger [] {cmt[0], cmt[1], pedersen_nonce};
	}

	/** @return [pedersen_hash_x, pedersen_hash_y, nonce_used] */
	public BigInteger [] logical_pedersen(ZaConfig config, BigInteger pedersen_nonce, BigInteger q){
		common cm = new common();
		ZaPedersenFull pedhash = new ZaPedersenFull(config, null);
		BigInteger [] cmt = pedhash.logical_eval(new BigInteger[]{}, 
			new BigInteger[] {pedersen_nonce, q});
		return new BigInteger [] {cmt[0], cmt[1], pedersen_nonce};
	}

	/** @return [pedersen_hash, nonce_used] */
	public Wire [] pedersen(ZaConfig config, Wire q, ZaGenerator zg){
		BigInteger bi_pedersen_nonce = gen_pedersen_nonce(config);
		Wire pedersen_nonce = zg.createConstantWire(bi_pedersen_nonce); 
		ZaPedersenFull pedhash = new ZaPedersenFull(config, zg);
		pedhash.build_circuit(new Wire []{}, new Wire [] {pedersen_nonce, q});
		Wire [] cmt = pedhash.getOutputWires();
		return new Wire [] {cmt[0], cmt[1], pedersen_nonce};
	}

	public Wire hash(Wire w1, Wire w2, ZaConfig config, ZaGenerator zg){
		ZaHash2 hash = ZaHash2.new_hash(config, zg); 
		hash.build_circuit(new Wire []{}, new Wire [] {w1, w2});
		Wire temp = hash.getOutputWires()[0];
		return temp;
	}

	public BigInteger logical_hash(BigInteger w1, BigInteger w2, ZaConfig config, ZaGenerator zg){
		ZaHash2 hash = ZaHash2.new_hash(config, zg); 
		BigInteger res = hash.logical_eval(new BigInteger []{}, new BigInteger [] {w1, w2})[0];
		return res;
	}


}
