/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/28/2021
* ***************************************************/

/** **************************************************
This is a verifier for a the deposit request from the
Fund side. It basically is  a simplified ZaDepositVerifier,
but for the update of the cash cert only
* ****************************************************/
package za_interface.za.circs.zero_audit;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
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
import za_interface.za.circs.range.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.encrypt.hybrid.*;
import util.Util;

/** **************************************************
This is a verifier for a the deposit request from the
Fund side. It basically is  a simplified ZaDepositVerifier,
but for the update of the cash cert only.
Note that the cash_diff should always be a positive number,
and later the server should check that it matches the
shares * NAV of the fund to purchase.

Public Input:
		ts, root_dbAcc, new_cash_cert_root, serial_no_cash, cash_diff
Private Witness:
		witness_cert_replace_cash
* ***************************************************/
public class ZaDepositVerifier extends ZaCirc{
	// *** data members ***
	protected Fund fund;
	protected PriceServer ps;
	protected Accumulator dbAcc;
	protected Cert old_cash_cert;
	protected Cert new_cash_cert;
	protected BigInteger nonce_hash_cash;

	//** private data members for keeping track of structure of proof
	private int idxCertCash; 

	// *** Operations ***
	/** It is assumed that the NEW cash cert is the latest in fund*/
	public ZaDepositVerifier(ZaConfig config_in, Fund fund, PriceServer ps, Accumulator dbAcc, ZaGenerator zg){
		super(config_in, "DepositVerifier", zg);
		this.fund = fund;
		this.ps = ps;
		this.dbAcc = dbAcc;
		this.old_cash_cert = fund.arrCerts.get(0).get(
				fund.arrCerts.get(0).size()-2);
		this.new_cash_cert = fund.arrCerts.get(0).get(
				fund.arrCerts.get(0).size()-1);
		this.nonce_hash_cash = Utils.randbi(249);
	
		this.idxCertCash = 2;
	}


	/** 
		ts, root_dbAcc, hash_old_cash_root, new_cash_cert_root, serial_no_cash, cash_diff, fund_id 
	 */
	public int getNumPublicInputs(){
		int res = 6 + dbAcc.get_hash().length;
		return res;
	}

	/** 
		witness_cert_replace_cash,
	*/
	public int getNumWitnessInputs(){
		ZaCertReplaceVerifier zcr = new ZaCertReplaceVerifier(config,
			old_cash_cert, new_cash_cert, dbAcc, Utils.itobi(1),
			Utils.itobi(1), 
			new_cash_cert.ts, Utils.itobi(0), Utils.itobi(10), null);		
		return zcr.getNumWitnessInputs();
	}

	/**
		Either 1 or 0 for yes or no.
	*/	
	public int getNumOutputs(){ 
		return 1;
	}


	/** 
		@arrPubInput - see getNumInputs
		@arrWitness - see getNumWitness 
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. Take out the inputs from arrPub and arrWitness
		ZaGenerator zg = (ZaGenerator) this.generator;
		int dbacc_len = dbAcc.get_hash().length;
		BigInteger order = config.getFieldOrder();
		BigInteger one = Utils.itobi(1);
		BigInteger [] ap = arrPubInput;
		BigInteger [] aw = arrWitness;
		BigInteger res = one;

		//2. call ZaCertReplace to check for cash replacement
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			nonce_hash_cash, fund.fund_id, one, one, one, zg);
		int dbacclen = dbAcc.get_hash().length;
		BigInteger [] dbAcc_root = Utils.slice(ap, 1, dbacc_len); 
		BigInteger [] pi_cash = new BigInteger [] {
			ap[0], ap[dbacclen+1], ap[dbacclen+2]
		};
		pi_cash = Utils.concat(pi_cash, dbAcc_root);
		pi_cash = Utils.concat(pi_cash, new BigInteger [] {ap[3+dbacclen]});
		BigInteger rcash = zcash.logical_eval( pi_cash, aw )[0];
		res = res.and(rcash);

		//4. check the match of all related attributes
		//all OTHERS checked, just need to check: sid is 0 and diff_cash 
		// is as expected, and fid is right
		common cm = new common();
		BigInteger zero = Utils.itobi(0);
		res = res.and( cm.logical_checkVal(aw, 0, ap[5+dbacclen], "pk@cash_cert=@fund_id") );
		res = res.and( cm.logical_checkVal(aw, 1, zero, "sid@cash_cert=0") );
		res = res.and( cm.logical_checkVal(aw, 2, ap[4+dbacclen], "cashDiff=aw[2]") );

		return new BigInteger [] {res};
	}


	/** build the circuit. Needs to supply the input wires
		@arrPubInput - see getNumInputs
		@arrWitness - see getNumWitness 
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. Take out the inputs from arrPub and arrWitness
		ZaGenerator zg = (ZaGenerator) this.generator;
		int dbacc_len = dbAcc.get_hash().length;
		Wire one = zg.createConstantWire(1);
		Wire [] ap = arrPubInput;
		Wire [] aw = arrWitness;
		Wire res = one;
		BigInteger bone = Utils.itobi(1);

		//2. call ZaCertReplace to check for cash replacement
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			nonce_hash_cash, fund.fund_id, bone, bone, bone, zg);
		int dbacclen = dbAcc.get_hash().length;
		Wire [] dbAcc_root = Utils.slice(ap, 1, dbacc_len); 
		Wire [] pi_cash = new Wire [] {
			ap[0], ap[dbacclen+1], ap[dbacclen+2]
		};
		pi_cash = Utils.concat(pi_cash, dbAcc_root);
		pi_cash = Utils.concat(pi_cash, new Wire [] {ap[3+dbacclen]});
		zcash.build_circuit( pi_cash, aw );
		Wire rcash = zcash.getOutputWires()[0];
		res = res.and(rcash);

		//4. check the match of all related attributes
		//all OTHERS checked, just need to check: sid is 0 and diff_cash 
		// is as expected, and fid is right
		common cm = new common();
		Wire zero = zg.createConstantWire(0);
		res = res.and( cm.checkVal(aw, 0, ap[5+dbacclen], "pk@cash_cert=@fund_id") );
		res = res.and( cm.checkVal(aw, 1, zero, "sid@cash_cert=0") );
		res = res.and( cm.checkVal(aw, 2, ap[4+dbacclen], "cashDiff=aw[2]") );

		return new Wire [] {res};
	}
	
	/** Generate the random inputs.  The inputs are actually NOT random,
		it is determined by the given cert in the constructor. To really
		randomize it - randomize the Fund 
	*/
	public BigInteger[][] genRandomInput(int n){
		//1. construct pub input
		BigInteger order = config.getFieldOrder();
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaHash2 hash = ZaHash2.new_hash(config, null);
		BigInteger hash_cash_old = hash.hash2(old_cash_cert.getRoot(), this.nonce_hash_cash);
		BigInteger zero = Utils.itobi(0);
		BigInteger one = Utils.itobi(1);
		BigInteger cash_diff= new_cash_cert.getQ().subtract(old_cash_cert.getQ()).mod(order);
		BigInteger [] arrInp = 	new BigInteger [] {
				new_cash_cert.ts, 
		};
		arrInp = Utils.concat(arrInp, dbAcc.get_hash());
		arrInp = Utils.concat(arrInp, new BigInteger [] {
			hash_cash_old, 
			new_cash_cert.root, 
			old_cash_cert.serial_no, 
			cash_diff,
			new_cash_cert.pk	
		});

		//2. arrWit for price verifier
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			this.nonce_hash_cash, fund.fund_id, new_cash_cert.ts,
			new_cash_cert.SID, cash_diff, zg);
		BigInteger [] arrWit = zcash.genRandomInput(0)[1]; 
	
		//6. return data
		return new BigInteger [][] {
			arrInp,
			arrWit
		};
	}

	// ------------------------------------------------------------------------
	// ---------------- The following are subroutinges called by local_eval ---
	// ------------------------------------------------------------------------


	/** check if the cash and stock replacements are performed well and
the difference in quantity matches the price * share_diff */
	protected BigInteger logical_eval_check_cert_replace(BigInteger [] arrPubInput, BigInteger [] arrWitness){
/*
		//1. Take out the inputs from arrPub and arrWitness
		ZaGenerator zg = (ZaGenerator) this.generator;
		int dbacc_len = dbAcc.get_hash().length;
		BigInteger order = config.getFieldOrder();
		BigInteger one = Utils.itobi(1);
		BigInteger [] ap = arrPubInput;
		BigInteger [] aw = arrWitness;
		BigInteger res = Utils.itobi(1);
		BigInteger new_ts = arrPubInput[0];
		BigInteger pk = aw[idxCertCash]; 
		BigInteger nonce_hash_cash = aw[idxCertCash+3];
		BigInteger nonce_hash_stock = aw[idxCertStock+3];
		BigInteger hash_old_cash_root = ap[2+dbacc_len];
		BigInteger new_cash_root = ap[2+dbacc_len+1];
		BigInteger hash_old_stock_root = ap[2+dbacc_len+2];
		BigInteger new_stock_root =ap[2+dbacc_len+3];
		BigInteger [] dbAcc_root = Utils.slice(ap, 2, dbacc_len); 
		BigInteger cash_id = Utils.itobi(0);
		BigInteger sid = aw[1]; //sid in proof_price
		BigInteger price = aw[2]; 
		BigInteger bBuy = aw[idxBuyDecision];
		BigInteger shares = aw[idxBuyDecision+1];
		BigInteger stock_diff = bBuy.equals(one)? shares: order.subtract(shares);
		BigInteger cash_serial = ap[6+dbacc_len];
		BigInteger stock_serial =ap[7+dbacc_len];
		BigInteger cash_diff = shares.multiply(price);
		cash_diff = bBuy.equals(one)? order.subtract(cash_diff): cash_diff;  

		//2. call ZaCertReplace to check for cash replacement
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			nonce_hash_cash, pk, new_ts,
			cash_id, cash_diff, zg);
		BigInteger [] pi_cash = new BigInteger [] {new_ts, hash_old_cash_root, new_cash_root};
		pi_cash = Utils.concat(pi_cash, dbAcc_root);
		pi_cash = Utils.concat(pi_cash, new BigInteger [] {cash_serial});
		int lencr = zcash.getNumWitnessInputs(); 
		BigInteger rcash = zcash.logical_eval(
			pi_cash, Utils.slice(arrWitness, idxCertCash, lencr)
		)[0];
		res = res.and(rcash);

		//3. call ZaCertReplace for shares_replacement
		ZaCertReplaceVerifier zstock = new ZaCertReplaceVerifier(config,
			this.old_stock_cert, this.new_stock_cert, this.dbAcc,
			nonce_hash_stock, pk, new_ts,
			sid, stock_diff, zg);
		BigInteger [] pi_stock = new BigInteger [] {new_ts, hash_old_stock_root, new_stock_root};
		pi_stock = Utils.concat(pi_stock, dbAcc_root);
		pi_stock = Utils.concat(pi_stock, new BigInteger [] {stock_serial});
	
		BigInteger rstock = zstock.logical_eval(
			pi_stock, Utils.slice(arrWitness, idxCertStock, lencr)
		)[0];
		res = res.and(rstock);

		//4. check the match of all related attributes
		//NOTE: ts_new, hash(old_cert), new_cert_root, root_dbAcc_tree
		//have been built into CertReplaceVerifiers's pubInput, no need
		//to verify them. We still need to verify:
		//pk, sid, cash_diff, stock_diff
		BigInteger zero = Utils.itobi(0);
		res = res.and( logical_checkVal(aw, idxCertStock, aw[idxCertStock], "pk@cash_cert=@stock_cert") );
		res = res.and( logical_checkVal(aw, idxCertCash+1, zero, "sid@cash_cert=0") );
		res = res.and( logical_checkVal(aw, idxCertStock+1, sid, "sid@cash_cert=sid in price proof") );
		res = res.and( logical_checkVal(aw, idxCertCash+2, cash_diff, "q_diff@cash_replace_proof") );
		res = res.and( logical_checkVal(aw, idxCertStock+2, stock_diff, "q_diff@stock_replace_proof") );

		return res;
*/
		return Utils.itobi(0);
	}

	
	// ------------------------------------------------------------------------
	// ---------------- subroutines for build_circuit --------------------- ---
	// ------------------------------------------------------------------------

	/** check if the cash and stock replacements are performed well and
the difference in quantity matches the price * share_diff */
	protected Wire build_circuit_check_cert_replace(Wire [] arrPubInput, Wire [] arrWitness){
/*
		//1. Take out the inputs from arrPub and arrWitness
		ZaGenerator zg = (ZaGenerator) this.generator;
		int dbacc_len = dbAcc.get_hash().length;
		Wire one = zg.createConstantWire(1);
		Wire zero = zg.createConstantWire(0);
		Wire [] ap = arrPubInput;
		Wire [] aw = arrWitness;
		Wire res = one;
		Wire new_ts = ap[0];
		Wire pk = aw[idxCertCash]; 
		Wire nonce_hash_cash = aw[idxCertCash+3];
		Wire nonce_hash_stock = aw[idxCertStock+3];
		Wire hash_old_cash_root = ap[2+dbacc_len];
		Wire new_cash_root = ap[2+dbacc_len+1];
		Wire hash_old_stock_root = ap[2+dbacc_len+2];
		Wire new_stock_root =ap[2+dbacc_len+3];
		Wire [] dbAcc_root = Utils.slice(ap, 2, dbacc_len); 
		Wire cash_id = zero;
		Wire sid = aw[1]; //sid in proof_price
		Wire price = aw[2]; 
		Wire bBuy = aw[idxBuyDecision];
		Wire shares = aw[idxBuyDecision+1];
		Wire stock_diff = bBuy.mul(shares).add(one.sub(bBuy).mul(zero.sub(shares)));
		Wire cash_serial = ap[6+dbacc_len];
		Wire stock_serial =ap[7+dbacc_len];
		Wire cash_diff = shares.mul(price);
		cash_diff = bBuy.mul(zero.sub(cash_diff)).add(one.sub(bBuy).mul(cash_diff));  

		//2. call ZaCertReplace to check for cash replacement
		BigInteger dummy = Utils.itobi(0); //doesn't matter, dummy value
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			dummy, dummy, dummy,
			dummy, dummy, zg);
		Wire [] pi_cash = new Wire [] {new_ts, hash_old_cash_root, 
			new_cash_root};
		pi_cash = Utils.concat(pi_cash, dbAcc_root);
		pi_cash = Utils.concat(pi_cash, new Wire [] {cash_serial});
		int lencr = zcash.getNumWitnessInputs(); 
		zcash.build_circuit(
			pi_cash, Utils.slice(arrWitness, idxCertCash, lencr)
		);
		Wire rcash = zcash.getOutputWires()[0];
		res = res.and(rcash);

		//3. call ZaCertReplace for shares_replacement
		ZaCertReplaceVerifier zstock = new ZaCertReplaceVerifier(config,
			this.old_stock_cert, this.new_stock_cert, this.dbAcc,
			dummy, dummy, dummy,
			dummy, dummy, zg);
		Wire [] pi_stock = new Wire [] {new_ts, hash_old_stock_root, new_stock_root};
		pi_stock = Utils.concat(pi_stock, dbAcc_root);
		pi_stock = Utils.concat(pi_stock, new Wire [] {stock_serial});
	
		zstock.build_circuit(
			pi_stock, Utils.slice(arrWitness, idxCertStock, lencr)
		);
		Wire rstock = zstock.getOutputWires()[0];
		res = res.and(rstock);

		//4. check the match of all related attributes
		//NOTE: ts_new, hash(old_cert), new_cert_root, root_dbAcc_tree
		//have been built into CertReplaceVerifiers's pubInput, no need
		//to verify them. We still need to verify:
		//pk, sid, cash_diff, stock_diff
		res = res.and( checkVal(aw, idxCertStock, aw[idxCertStock], "pk@cash_cert=@stock_cert") );
		res = res.and( checkVal(aw, idxCertCash+1, zero, "sid@cash_cert=0") );
		res = res.and( checkVal(aw, idxCertStock+1, sid, "sid@cash_cert=sid in price proof") );
		res = res.and( checkVal(aw, idxCertCash+2, cash_diff, "q_diff@cash_replace_proof") );
		res = res.and( checkVal(aw, idxCertStock+2, stock_diff, "q_diff@stock_replace_proof") );

		return res;
*/
		return null;
	}


}
