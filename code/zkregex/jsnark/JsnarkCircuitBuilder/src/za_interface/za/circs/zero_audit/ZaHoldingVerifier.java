/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/21/2021
Modified: 06/27/2021 -> use PedersenFull to replace
Pedersen, so that the full point is used in computing
homomorphic commitment
* ***************************************************/

/** **************************************************
This is a verifier for a certifying a fund ID has
a certain number of shares of stocks expressed
in the form of Pedersen commitment. Note that the
shares is HIDDEN but the (pk, sid, ts) is PUBLIC.
It is adapted from cert replacement verifier.
The basic idea is to prove that there are two consecutive
certs around the given ts has the specified number of
shares. The commit is done using Pedersen
commitment based on elliptic curve arith, note that
curve properties decided separately by ZaConfig.

public input:
  pk (fund_id), sid, commit_in_curve_point(shares), ts, root_dbAcc_tree

private witness:
		nonce_pedersen, //used for generating pedersen_hash(shares)
		membership_proof_of_old_root,
		membership_proof_of_new_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
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
import za_interface.za.circs.hash.pedersen.*;
import za_interface.za.circs.range.*;
import util.Util;

/** **************************************************
This is a verifier for a certifying a fund ID has
a certain number of shares of stocks expressed
in the form of Pedersen commitment, at the given ts.

public input:
  pk (fund_id), sid, commit_in_curve_point(shares), ts, root_dbAcc_tree

private witness:
		nonce_pedersen, //used for generating pedersen_hash(shares)
		membership_proof_of_old_root,
		membership_proof_of_new_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
* ***************************************************/
public class ZaHoldingVerifier extends ZaCirc{
	// *** data members ***
	protected Cert old_cert;
	protected Cert new_cert;
	protected BigInteger ts_to_certify;
	protected Accumulator dbAcc; //the database of certs

	// *** Operations ***
	/** constructor */
	public ZaHoldingVerifier(ZaConfig config_in, Cert old_cert, Cert new_cert, BigInteger ts_to_certify, Accumulator dbAcc, ZaGenerator zg){
		super(config_in, "HoldingVerifier", zg);
		this.old_cert = old_cert;
		this.new_cert = new_cert;
		this.dbAcc = dbAcc;
		this.ts_to_certify = ts_to_certify;
	}


	/** public inputs:
  		pk (fund_id), sid, commit_in_point(shares), ts, root_dbAcc_tree
	*/
	public int getNumPublicInputs(){
		return 5 + dbAcc.get_hash().length;
	}

	/**
		nonce_pedersen, //used for generating pedersen_hash(shares)
		membership_proof_of_old_root,
		membership_proof_of_new_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
	*/
	public int getNumWitnessInputs(){
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		int cert_proof_size = zcv.getNumWitnessInputs();
		int membership_size = dbAcc.genAccumulatorVerifier(null).getNumWitnessInputs();
		return 1+ 2*cert_proof_size + 2*membership_size;
	}

	/**
		Either 1 or 0 for yes or no. Any exception returns 0.
	*/	
	public int getNumOutputs(){ 
		return 1;
	}


	/**  Logically evaluate the input
public input:
  pk (fund_id), sid, commit_in_point(shares), ts, root_dbAcc_tree

private witness:
		nonce_pedersen, //used for generating pedersen_hash(shares)
		membership_proof_of_old_root,
		membership_proof_of_new_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//0. set up the inputs
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		BigInteger [] pi = arrPubInput;
		BigInteger [] aw = arrWitness;
		BigInteger res = Utils.itobi(1); 
		BigInteger order = config.getFieldOrder();
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		ZaAccumulatorVerifier zav = dbAcc.genAccumulatorVerifier(zg);
		int idxMember1 = 1;
		int idxMember2 = idxMember1 + zav.getNumWitnessInputs(); 
		int idxCert1 = idxMember2 + zav.getNumWitnessInputs();
		int idxCert2 = idxCert1 + zcv.getNumWitnessInputs();
		common cm = new common();

		//2. check the public inputs
		res = res.and(cm.logical_checkVal(pi, 0, aw[idxCert1], "pk@cert1"));
		res = res.and(cm.logical_checkVal(pi, 0, aw[idxCert2], "pk@cert2"));
		res = res.and(cm.logical_checkVal(pi, 1, aw[idxCert1+3], "sid@cert1"));
		res = res.and(cm.logical_checkVal(pi, 1, aw[idxCert2+3], "sid@cert1"));
		BigInteger [] ped_res = cm.logical_pedersen(config, aw[idxCert1+4]);
		res = res.and(cm.logical_checkVal(pi, 2, ped_res[0], "commit(shares)[0]"));
		res = res.and(cm.logical_checkVal(pi, 3, ped_res[1], "commit(shares)[1]"));
		res = res.and(cm.logical_checkVal(aw, 0, ped_res[2], "commit nonce"));
		int root_len = dbAcc.get_hash().length;
		for(int i=0; i<root_len; i++){
		  res=res.and(cm.logical_checkVal(pi,5,aw[idxMember1+1+i], "member1"));
		  res=res.and(cm.logical_checkVal(pi,5,aw[idxMember2+1+i], "member2"));
		}

		//3. check the matching of pairwise 6 attributes of two certs
		//but skip pk, nonce, SID, q, check: counter and root and ts
		BigInteger one = Utils.itobi(1);
		BigInteger resc = cm.logical_checkVal(aw, idxCert1+1, aw[idxCert2+1].subtract(one), "counter") ; //new_counter = old_counter + 1
		res = res.and(resc);
		res = res.and(cm.logical_checkVal(aw, idxCert1+6, aw[idxMember1], "root@cert1 in membership proof") );
		res = res.and(cm.logical_checkVal(aw, idxCert2+6, aw[idxMember2], "root@cert2 in membership proof") );
		res = res.and(logical_isLE(aw[idxCert1+5], pi[4],true,"cert1.ts<=ts"));
		res = res.and(logical_isLE(pi[4], aw[idxCert2+5],false, "ts<cert2"));
		

		//4. check the valid cert proof
		ZaCertVerifier z1 = new ZaCertVerifier(config, old_cert, zg);
		int zclen = z1.getNumWitnessInputs();
		res = res.and(cm.logical_checkTrue(
			z1.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxCert1, zclen))[0], "valid old_cert")
		);

		//5. check the valid cert2 proof
		ZaCertVerifier z2 = new ZaCertVerifier(config, new_cert, zg);
		res = res.and(cm.logical_checkTrue(
			z2.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxCert2, zclen))[0], "valid new_cert")
		);

		//6. check the valid membership proof
		ZaAccumulatorVerifier zav1 = dbAcc.genAccumulatorVerifier(zg);
		res = res.and(cm.logical_checkTrue(
			zav1.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxMember1, zav.getNumWitnessInputs()))[0], 
			"valid dbacc membership proof1")
		);

		ZaAccumulatorVerifier zav2 = dbAcc.genAccumulatorVerifier(zg);
		res = res.and(cm.logical_checkTrue(
			zav2.logical_eval(new BigInteger [] {}, 
			Utils.slice(aw, idxMember2, zav.getNumWitnessInputs()))[0], 
			"valid dbacc membership proof2")
		);

		//7. return all
		return new BigInteger [] {res};
	}


	/** For inputs layout: check logical_eval
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//0. set up the inputs
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		Wire [] pi = arrPubInput;
		Wire [] aw = arrWitness;
		Wire res = this.generator.createConstantWire(1);
		ZaCertVerifier zcv = new ZaCertVerifier(config, old_cert, null);
		ZaAccumulatorVerifier zav = dbAcc.genAccumulatorVerifier(zg);
		int idxMember1 = 1;
		int idxMember2 = idxMember1 + zav.getNumWitnessInputs(); 
		int idxCert1 = idxMember2 + zav.getNumWitnessInputs();
		int idxCert2 = idxCert1 + zcv.getNumWitnessInputs();
		common cm = new common();

		//2. check the public inputs (ts is checked later)
		res = res.and(cm.checkVal(pi, 0, aw[idxCert1], "pk@cert1"));
		res = res.and(cm.checkVal(pi, 0, aw[idxCert2], "pk@cert2"));
		res = res.and(cm.checkVal(pi, 1, aw[idxCert1+3], "sid@cert1"));
		res = res.and(cm.checkVal(pi, 1, aw[idxCert2+3], "sid@cert1"));
		Wire [] ped_res = cm.pedersen(config, aw[idxCert1+4], (ZaGenerator) generator);
		res = res.and(cm.checkVal(pi, 2, ped_res[0], "commit(shares)[0]"));
		res = res.and(cm.checkVal(pi, 3, ped_res[1], "commit(shares)[1]"));
		res = res.and(cm.checkVal(aw, 0, ped_res[2], "commit nonce"));
		int root_len = dbAcc.get_hash().length;
		for(int i=0; i<root_len; i++){
		  res=res.and(cm.checkVal(pi,5,aw[idxMember1+1+i], "member1"));
		  res=res.and(cm.checkVal(pi,5,aw[idxMember2+1+i], "member2"));
		}

		//3. check the matching of pairwise 6 attributes of two certs
		//but skip pk, nonce, SID, q, check: counter and root
		Wire one = this.generator.createConstantWire(1);
		Wire resc = cm.checkVal(aw, idxCert1+1, aw[idxCert2+1].sub(one), "counter") ; //new_counter = old_counter + 1
		res = res.and(resc);
		res = res.and(cm.checkVal(aw, idxCert1+6, aw[idxMember1], "root@cert1 in membership proof") );
		res = res.and(cm.checkVal(aw, idxCert2+6, aw[idxMember2], "root@cert2 in membership proof") );
		res = res.and(isLE(aw[idxCert1+5], pi[4],true,"cert1.ts<=ts"));
		res = res.and(isLE(pi[4], aw[idxCert2+5],false, "ts<cert2"));
		
		

		//4. check the valid cert proof
		ZaCertVerifier z1 = new ZaCertVerifier(config, old_cert, zg);
		int zclen = z1.getNumWitnessInputs();
		z1.build_circuit(new Wire [] {}, Utils.slice(aw, idxCert1, zclen));
		res = res.and(cm.checkTrue(z1.getOutputWires()[0], "cert1 valid"));

		//5. check the valid cert2 proof
		ZaCertVerifier z2 = new ZaCertVerifier(config, new_cert, zg);
		z2.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxCert2, zclen));
		res = res.and(cm.checkTrue(z2.getOutputWires()[0], "cert2 valid"));

		//6. check the valid membership proof
		ZaAccumulatorVerifier zav1 = dbAcc.genAccumulatorVerifier(zg);
		zav1.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxMember1, zav.getNumWitnessInputs()));
		res = res.and(cm.checkTrue( 
			zav1.getOutputWires()[0], "valid dbacc membership proof1"));

		ZaAccumulatorVerifier zav2 = dbAcc.genAccumulatorVerifier(zg);
		zav2.build_circuit(new Wire [] {}, 
			Utils.slice(aw, idxMember2, zav.getNumWitnessInputs()));
		res = res.and(cm.checkTrue(
			zav2.getOutputWires()[0], "valid dbacc membership proof2"));

		//7. return all
		return new Wire [] {res};
	}


	/** Generate the random inputs.  The inputs are actually NOT random,
		The data generated is completely dependent on
		the cert given 
public input:
  pk (fund_id), sid, commit_in_point(shares), ts, root_dbAcc_tree

private witness:
		nonce_commit_hash, //used for generating pedersen hash
		membership_proof_of_old_root,
		membership_proof_of_new_root,
		valid_proof_of_old_cert,
		valid_proof_of_new_cert
	*/
	public BigInteger[][] genRandomInput(int n){
		//0. Create Pedersen commit as it's homormorphic
		common cm = new common();
		BigInteger [] ped_res = cm.logical_pedersen(config, old_cert.q);
		
		//1. generate the public input
		BigInteger commit_shares = Utils.itobi(0);
		BigInteger [] pubinp = new BigInteger [] {
			old_cert.pk,
			old_cert.SID,
			ped_res[0], 
			ped_res[1], 
			this.ts_to_certify
		};
		BigInteger [] dbacc_root = dbAcc.get_hash();
		pubinp = Utils.concat(pubinp, dbacc_root);

		//2. generate the membership and valid proofs
		BigInteger [] arrwit = new BigInteger [] { ped_res[2]};
		BigInteger [] prfOldCert= dbAcc.gen_witness(old_cert.getRoot());
		arrwit = Utils.concat(arrwit, prfOldCert);
		BigInteger [] prfNewCert= dbAcc.gen_witness(new_cert.getRoot());
		arrwit = Utils.concat(arrwit, prfNewCert);
		ZaCertVerifier zc1 = new ZaCertVerifier(config, this.old_cert, null);
		BigInteger [] cert1_proof = zc1.genRandomInput(0)[1]; //witness	
		arrwit = Utils.concat(arrwit, cert1_proof);
		ZaCertVerifier zc2 = new ZaCertVerifier(config, this.new_cert, null);
		BigInteger [] cert2_proof = zc2.genRandomInput(0)[1]; //witness	
		arrwit = Utils.concat(arrwit, cert2_proof);

		//3. return
		return new BigInteger [][] {pubinp, arrwit};
	}

	//---- ASSISTING FUNCTIONS ---------------------	
	/** check if a<=b if bAllowEq is set; otherwise check if a<b */
	protected BigInteger logical_isLE(BigInteger a, BigInteger b,
		boolean bAllowEq, String msg){
		if(a.compareTo(b)<=0 && (bAllowEq || !a.equals(b)) ){
			return Utils.itobi(1);
		}else{
			Utils.log(Utils.LOG1, "WARNING: " + msg + " is false");
			return Utils.itobi(0);
		}
	}

	/** check if a<=b if bAllowEq is set; otherwise check if a<b;
		Treat the difference as 64-bit non-negative numbers */
	protected Wire isLE(Wire a, Wire b,
		boolean bAllowEq, String msg){
		//1. inputs
		ZaGenerator zg = (ZaGenerator) this.generator;
		Wire diff = b.sub(a);
		Wire zero = this.generator.createConstantWire(0);
		Wire one= this.generator.createConstantWire(1);
		Wire wAllowEq = bAllowEq? one: zero;
		Wire wNotAllowEq = !bAllowEq? one: zero;

		//2. check if a<=b
		ZaRange za = new ZaRange(config, 64, zg);
		za.build_circuit(new Wire [] {}, new Wire [] {diff});
		Wire bLE = za.getOutputWires()[0];

		//3. handle two cases on bAllowEq
		Wire bEq = a.isEqualTo(b);
		Wire bNotEq = one.sub(bEq);
		//(wAllowEQ=1: bLE), (wAllowEQ=0: bLE & bNOTEq
		Wire res = wAllowEq.and(bLE).or(
			wNotAllowEq.and(bLE).and(bNotEq)
		);
		return res;
	}
}
