/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/14/2021
* ***************************************************/

/** **************************************************
This is a verifier for a replacement replace between
two certs:
pubInput: ts_new, hash(old_cert_root), new_cert_root, root_dbAcc_tree,
		serial_no_old_cert (as spending ticket)
privWitness: nonce_used_in_hash_old_cert_root,
        membership_proof_of_old_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
Output: 1 or 0 for valid replacement relation
Note: its constructor takes the desired pk, new_ts, sid, q_diff
and these values will be checked
* ***************************************************/
package za_interface.za.circs.zero_audit;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import circuit.structure.Wire;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.range.*;
import util.Util;

/** **************************************************
This is a verifier for a replacement replace between
two certs:
pubInput: ts_new, hash(old_cert_root), new_cert_root, root_dbAcc_tree.
privWitness: nonce_used_in_hash_old_cert_root,
        membership_proof_of_old_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
Output: 1 or 0 for valid replacement relation
NOTE: the pk, sid, q_diff need to be CHECKED OUTSIDE of 
ZaCertReplaceVerifier. 
* ***************************************************/
public class ZaCertReplaceVerifier extends ZaCirc{
	// *** data members ***
	protected Cert old_cert;
	protected Cert new_cert;
	protected BigInteger nonce_hash;
	protected Accumulator dbAcc; //the database of certs
	protected ZaHash2 hash;
	protected BigInteger pk; //needs to be checked outside
	protected BigInteger new_ts; //needs to be checked outside
	protected BigInteger sid; //needs to be checked outisde
	protected BigInteger q_diff; //needs to be checked outside

	// *** Operations ***
	/** Need to pass the old and new certs, the Accumulator and the random nonce to use  for hasing the old cert*/
	public ZaCertReplaceVerifier(ZaConfig config_in, Cert old_cert, Cert new_cert, Accumulator dbAcc, BigInteger nonce_hash, BigInteger pk, 
BigInteger new_ts, BigInteger sid, BigInteger q_diff, ZaGenerator zg){
		super(config_in, "CertReplaceVerifier", zg);
		this.old_cert = old_cert;
		this.new_cert = new_cert;
		this.nonce_hash = nonce_hash;
		this.dbAcc = dbAcc;
		this.hash = ZaHash2.new_hash(config_in, zg);

		//these are passed as a conveinence for building genRandINput
		//when ZaCertRepalceVerifier called and built, the following
		//inputs have to be checked OUTSIDE of ZaCertReplaceVerifier!
		this.pk = pk;
		this.new_ts = new_ts;
		this.sid = sid;
		this.q_diff = q_diff;
		
	}


	/** public inputs:
	 	ts_new, hash(old_cert_root), new_cert_root, root_dbAcc_tree, 
		serial_no_old */
	public int getNumPublicInputs(){
		return 4 + dbAcc.get_hash().length;
	}

	/**
		pk, sid, q_diff, nonce_hash_old_root,
		valid_cert_proof_old (pk, counter, nonce, SID, q, ts, root),
		valid_cert_proof_new, 	
		valid_membership_old_cert (element, root_hash, path_proof)
	*/
	public int getNumWitnessInputs(){
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		int cert_proof_size = zcv.getNumWitnessInputs();
		int membership_size = dbAcc.genAccumulatorVerifier(null).getNumWitnessInputs();
		return 4 + 2*cert_proof_size + membership_size;
	}

	/**
		Either 1 or 0 for yes or no
	*/	
	public int getNumOutputs(){ 
		return 1;
	}

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

	/** 
	 public inputs:
	 	ts_new, hash(old_cert_root), new_cert_root, root_dbAcc_tree
	 private_witness:	
		pk, sid, q_diff, nonce_hash,
		valid_cert_proof_old (pk, counter, nonce, SID, q, ts, root),
		valid_cert_proof_new, 	
		valid_membership_old_cert (element, root_hash, path_proof).

		For "real" randomness, randomize the input certs.
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. check the matching of inputs and corresponding cert proof
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		BigInteger [] pi = arrPubInput;
		BigInteger [] aw = arrWitness;
		BigInteger res = Utils.itobi(1); 
		BigInteger order = config.getFieldOrder();
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		int idxCert1 = 4;
		int idxCert2 = 4 + zcv.getNumWitnessInputs();
		int idxMembership= 4 + 2*zcv.getNumWitnessInputs();
		res = res.and( logical_checkVal(pi, 0, aw[idxCert2+5], "new_ts@cert2") );
		BigInteger hash_old_root = this.hash.hash2(aw[idxCert1+6], aw[3]);
		res = res.and( logical_checkVal(pi, 1, hash_old_root, "hash_old_root") );
		res = res.and( logical_checkVal(pi, 2, aw[idxCert2+6], "new_cert_root") );
		int root_len = dbAcc.get_hash().length;
		for(int i=0; i<root_len; i++){
			res = res.and(logical_checkVal(pi, 3+i, aw[idxMembership+1+i], "new_cert_root"));
		}
		ZaHash2 hash = ZaHash2.new_hash(config, zg);
		BigInteger temp =hash.hash2(aw[4], aw[5]); //hash(pk, counter)
		BigInteger serial_no = hash.hash2(temp, aw[6]); //hash(temp, nonce);
		res = res.and( logical_checkVal(pi, 3+root_len, serial_no, "serial_no") );

		//2. check the matching of arrwit 5 elements
		res = res.and( logical_checkVal(aw, 0, aw[idxCert1], "pk1") );
		res = res.and( logical_checkVal(aw, 0, aw[idxCert2], "pk2") );
		res = res.and( logical_checkVal(aw, 1, aw[idxCert1+3], "sid1") );
		res = res.and( logical_checkVal(aw, 1, aw[idxCert2+3], "sid2") );
		res = res.and( logical_checkVal(aw, 2, 
			aw[idxCert2+4].subtract(aw[idxCert1+4]).mod(order), "q_diff") );


		//3. check the matching of pairwise 6 attributes of two certs
		//but skip pk, q, SID, root because already checked
		BigInteger one = Utils.itobi(1);
		BigInteger resc = logical_checkVal(aw, idxCert1+1, aw[idxCert2+1].subtract(one), "counter") ; //new_counter = old_counter + 1
		res = res.and(resc);
		
		ZaRange zr3 = new ZaRange(config, 64, null);
		BigInteger res3 = zr3.logical_eval(new BigInteger [] {}, new BigInteger[] {aw[idxCert2+5].subtract(aw[idxCert1+5]).subtract(one).mod(order)})[0];
		res = res.and(logical_checkTrue(res3, "ts2>ts"));
		res = res.and( logical_checkVal(aw, idxCert1+6, aw[idxMembership], "oldroot_in_dbacc") );
		

		//4. check the valid cert proof
		ZaCertVerifier z1 = new ZaCertVerifier(config, old_cert, zg);
		int zclen = z1.getNumWitnessInputs();
		res = res.and(logical_checkTrue(
			z1.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxCert1, zclen))[0], "valid old_cert")
		);

		//5. check the valid cert2 proof
		ZaCertVerifier z2 = new ZaCertVerifier(config, new_cert, zg);
		res = res.and(logical_checkTrue(
			z2.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxCert2, zclen))[0], "valid new_cert")
		);

		//6. check the valid membership proof
		ZaAccumulatorVerifier zav = dbAcc.genAccumulatorVerifier(zg);
		res = res.and(logical_checkTrue(
			zav.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxMembership, zav.getNumWitnessInputs()))[0], 
			"valid dbacc membership proof")
		);

		//7. return all
		return new BigInteger [] {res};
	}


	/** For inputs layout: check logical_eval
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. check the matching of inputs and corresponding cert proof
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		Wire [] pi = arrPubInput;
		Wire [] aw = arrWitness;
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		int idxCert1 = 4;
		int idxCert2 = 4 + zcv.getNumWitnessInputs();
		int idxMembership= 4 + 2*zcv.getNumWitnessInputs();
		Wire res = checkVal(pi, 0, aw[idxCert2+5], "new_ts@cert2") ;
		ZaHash2 hash = ZaHash2.new_hash(config, zg);
		hash.build_circuit(new Wire [] {}, new Wire [] {aw[idxCert1+6], aw[3]});
		Wire hash_old_root = hash.getOutputWires()[0];
		res = res.and( checkVal(pi, 1, hash_old_root, "hash_old_root") );
		res = res.and( checkVal(pi, 2, aw[idxCert2+6], "new_cert_root") );
		int root_len = dbAcc.get_hash().length;
		for(int i=0; i<root_len; i++){
			res = res.and(checkVal(pi, 3+i, aw[idxMembership+1+i], "new_cert_root"));
		}
		ZaHash2 hash1 = ZaHash2.new_hash(config, zg);
		hash1.build_circuit(new Wire []{}, new Wire [] {aw[4], aw[5]});
		Wire temp =hash1.getOutputWires()[0];
		ZaHash2 hash2 = ZaHash2.new_hash(config, zg);
		hash2.build_circuit(new Wire[]{}, new Wire[] {temp, aw[6]});
		Wire serial_no = hash2.getOutputWires()[0];
		res = res.and( checkVal(pi, 3+root_len, serial_no, "serial_no") );

		//2. check the matching of arrwit 4 elements
		res = res.and( checkVal(aw, 0, aw[idxCert1], "pk1") );
		res = res.and( checkVal(aw, 0, aw[idxCert2], "pk2") );
		res = res.and( checkVal(aw, 1, aw[idxCert1+3], "sid1") );
		res = res.and( checkVal(aw, 1, aw[idxCert2+3], "sid2") );
		res = res.and( checkVal(aw, 2, 
			aw[idxCert2+4].sub(aw[idxCert1+4]), "q_diff") );

		//3. check the matching of pairwise 6 attributes of two certs
		//but skip pk, q, SID, root because already checked
		Wire one = zg.createConstantWire(1);
		Wire resc = checkVal(aw, idxCert1+1, aw[idxCert2+1].sub(one), "counter") ; //new_counter = old_counter + 1
		res = res.and(resc);
		
		ZaRange zr3 = new ZaRange(config, 64, zg);
		zr3.build_circuit(new Wire [] {}, new Wire[] {aw[idxCert2+5].sub(aw[idxCert1+5]).sub(one)});
		Wire res3 = zr3.getOutputWires()[0];
		res = res.and(checkTrue(res3, "ts2>ts"));

		res = res.and( checkVal(aw, idxCert1+6, aw[idxMembership], "oldroot_in_dbacc") );
		

		//4. check the valid cert proof
		ZaCertVerifier z1 = new ZaCertVerifier(config, old_cert, zg);
		int zclen = z1.getNumWitnessInputs();
		z1.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxCert1, zclen));
		res = res.and(checkTrue( z1.getOutputWires()[0], "valid old_cert"));


		//5. check the valid cert2 proof
		ZaCertVerifier z2 = new ZaCertVerifier(config, new_cert, zg);
		z2.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxCert2, zclen));
		res = res.and(checkTrue(z2.getOutputWires()[0], "valid new_cert"));

		//6. check the valid membership proof
		ZaAccumulatorVerifier zav = dbAcc.genAccumulatorVerifier(zg);
		zav.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxMembership, zav.getNumWitnessInputs()));
		res = res.and(checkTrue( zav.getOutputWires()[0], "valid dbacc membership proof"));

		//7. return all
		return new Wire [] {res};
	}

	
	/** Generate the random inputs.  The inputs are actually NOT random,
		The data generated is completely dependent on
		the cert given 
	 public inputs:
	 	ts_new, hash(old_cert_root), new_cert_root, root_dbAcc_tree
	 private_witness:	
		pk, sid, q_diff,
		valid_cert_proof_old (pk, counter, nonce, SID, q, ts, root),
		valid_cert_proof_new, 	
		valid_membership_old_cert (element, root_hash, path_proof).

		For "real" randomness, randomize the input certs.
	*/
	public BigInteger[][] genRandomInput(int n){
		//1. generate the public input
		BigInteger [] pubinp = new BigInteger [] {
			this.new_ts,
			this.hash.hash2(old_cert.getRoot(), nonce_hash),
			new_cert.getRoot()
		};
		BigInteger [] dbacc_root = dbAcc.get_hash();
		pubinp = Utils.concat(pubinp, dbacc_root);
		pubinp = Utils.concat(pubinp, new BigInteger [] {old_cert.serial_no});

		//2. generate the private witness
		BigInteger [] arrwit = new BigInteger [] {
			this.pk, this.sid, this.q_diff, this.nonce_hash
		};
		ZaCertVerifier zc1 = new ZaCertVerifier(config, this.old_cert, null);
		BigInteger [] cert1_proof = zc1.genRandomInput(0)[1]; //witness	
		arrwit = Utils.concat(arrwit, cert1_proof);
		ZaCertVerifier zc2 = new ZaCertVerifier(config, this.new_cert, null);
		BigInteger [] cert2_proof = zc2.genRandomInput(0)[1]; //witness	
		arrwit = Utils.concat(arrwit, cert2_proof);
		BigInteger [] prfOldCert= dbAcc.gen_witness(old_cert.getRoot());
		arrwit = Utils.concat(arrwit, prfOldCert);


		//3. return
		return new BigInteger [][] {pubinp, arrwit};
	}
	
}
