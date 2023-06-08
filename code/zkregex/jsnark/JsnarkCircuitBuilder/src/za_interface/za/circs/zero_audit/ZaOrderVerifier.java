/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/09/2021
* ***************************************************/

/** **************************************************
This is a verifier for a the request for 
a trading order (buy or sell). 

But we do not want to SHOW
which stock is being traded, the order number,
the fund that is involved, but we still want to show that
the transaction is valid (performed at the right price),
and the fund is still solvent, and the updates of quantities
of certificates are right. 

Two certificates (cash and stock)
will be replaced by two new certificates, and 
we will only know about the commitment of the two 
old cert roots. We also need to prove the correct values
in the encrypted instruction to the stock broker (see paper). 

The public input includes:
		ts, root_price_tree, root_dbAcc, hash(old_cash_cert_root), new_cash_cert_root, hash(old_stock_cert_root), new_stock_cert_root, serial_no_cash, serial_no_stock, encrypted_broker_instruction
The private witness includes:

The witness includes:
		witness_price_verifier [],
		buy_decision, shares, 
		witness_cert_replace_cash,
		witness_cert_replace_stock,
		witness_broker_instruction
	
* ***************************************************/
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
This is a verifier for a the request for 
a trading order (buy or sell).  But we do not want to SHOW
which stock is being traded, the order number,
the fund that is involved, but we still want to show that
the transaction is valid (performed at the right price),
and the fund is still solvent, and the updates of quantities
of certificates are right. 

* ***************************************************/
public class ZaOrderVerifier extends ZaCirc{
	// *** data members ***
	protected Fund fund;
	protected PriceServer ps;
	protected Accumulator dbAcc;
	protected BigInteger [] encryped_order;
	protected int sid;
	protected Cert old_cash_cert;
	protected Cert old_stock_cert;
	protected Cert new_cash_cert;
	protected Cert new_stock_cert;
	protected BigInteger old_ts;
	protected BigInteger new_ts;
	protected BigInteger nonce_hash_cash;
	protected BigInteger nonce_hash_stock;

	//** private data members for keeping track of structure of proof
	private int idxBuyDecision; 
	private int idxCertCash; 
	private int idxCertStock; 
	private int idxBroker;

	// *** Operations ***
	/** Assumption: the buy/sell operation is LOGICALLY performed
correct and the fund's new cert has been added for cach and sid logically. */
	public ZaOrderVerifier(ZaConfig config_in, Fund fund, int sid, PriceServer ps, Accumulator dbAcc, BigInteger [] encrypted_order, ZaGenerator zg){
		super(config_in, "OrderVerifier", zg);
		this.fund = fund;
		this.ps = ps;
		this.dbAcc = dbAcc;
		this.sid = sid;
		this.old_cash_cert = fund.arrCerts.get(0).get(
				fund.arrCerts.get(0).size()-2);
		this.new_cash_cert = fund.arrCerts.get(0).get(
				fund.arrCerts.get(0).size()-1);
		this.old_stock_cert = fund.arrCerts.get(sid).get(
				fund.arrCerts.get(sid).size()-2);
		this.new_stock_cert = fund.arrCerts.get(sid).get(
				fund.arrCerts.get(sid).size()-1);
		this.old_ts = old_cash_cert.ts;
		this.new_ts = new_cash_cert.ts;	
		this.nonce_hash_cash = Utils.randbi(249);
		this.nonce_hash_stock = Utils.randbi(249);
		
		ZaPriceVerifier pv = new ZaPriceVerifier(config, ps, null);
		ZaCertReplaceVerifier zcr = new ZaCertReplaceVerifier(config,
			old_cash_cert, new_cash_cert, dbAcc, Utils.itobi(1),
			Utils.itobi(1), 
			new_cash_cert.ts, Utils.itobi(sid), Utils.itobi(10), null);		
		this.idxBuyDecision = pv.getNumWitnessInputs();
		this.idxCertCash = idxBuyDecision + 2;
		this.idxCertStock = idxCertCash +  zcr.getNumWitnessInputs();
		this.idxBroker= idxCertStock+  zcr.getNumWitnessInputs();
	}


	/** 
		ts, root_price_tree, root_dbAcc, hash(old_cash_cert_root), new_cash_cert_root, hash(old_stock_cert_root), new_stock_cert_root, serial_no_cash, serial_no_stock, encrypted_broker_instruction
	 */
	public int getNumPublicInputs(){
		int res = 2 + dbAcc.get_hash().length + 4 + 2 + 2;
		return res;
	}

	/** 
		witness_price_verifier [],
		buy_decision, shares, 
		witness_cert_replace_cash,
		witness_cert_replace_stock,
		witness_broker_instruction
	*/
	public int getNumWitnessInputs(){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaPriceVerifier priceVerifier = new ZaPriceVerifier(config, ps, null);
		//note: params are fake just for getting input size
		ZaCertReplaceVerifier zcr = new ZaCertReplaceVerifier(config,
			old_cash_cert, new_cash_cert, dbAcc, Utils.itobi(1),
			Utils.itobi(1), 
			new_cash_cert.ts, Utils.itobi(sid), Utils.itobi(10), null);		
		ZaBrokerInstructionVerifier zb = new ZaBrokerInstructionVerifier(config, null);
		int res = priceVerifier.getNumWitnessInputs()
			+ 2
			+ zcr.getNumWitnessInputs()*2 +
			zb.getNumWitnessInputs();
		return res;
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
		BigInteger []data=logical_eval_check_decision(arrPubInput, arrWitness);
		BigInteger bres = data[0];
		BigInteger cash_diff = data[1];
		BigInteger shares_diff = data[2];
		bres = bres.multiply(logical_eval_checkPrice(arrPubInput, arrWitness));
		bres = bres.multiply(logical_eval_check_cert_replace(arrPubInput, arrWitness));
		bres = bres.multiply(logical_eval_check_broker(arrPubInput, arrWitness));
		return new BigInteger [] {bres};
	}


	/** build the circuit. Needs to supply the input wires
		@arrPubInput - see getNumInputs
		@arrWitness - see getNumWitness 
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		Wire []data=build_circuit_check_decision(arrPubInput, arrWitness);
		Wire bres = data[0];
		Wire cash_diff = data[1];
		Wire shares_diff = data[2];

		bres = bres.and(build_circuit_checkPrice(arrPubInput, arrWitness));
		bres = bres.and(build_circuit_check_cert_replace(arrPubInput, arrWitness));

		bres = bres.and(check_broker(arrPubInput, arrWitness));
		return new Wire [] {bres};
	}
	
	/** Generate the random inputs.  The inputs are actually NOT random,
		it is determined by the given cert in the constructor. To really
		randomize it - randomize the Fund 
	*/
	public BigInteger[][] genRandomInput(int n){
		//1. construct pub input
		BigInteger order = config.getFieldOrder();
		ZaGenerator zg = (ZaGenerator) this.generator;
		BigInteger zero = Utils.itobi(0);
		BigInteger one = Utils.itobi(1);
		ZaPriceVerifier priceVerifier = new ZaPriceVerifier(config, ps, zg);
		BigInteger [] arrInp = 	new BigInteger [] {
				new_ts, 
				ps.getRoot(new_ts.intValue()), 
		};
		arrInp = Utils.concat(arrInp, dbAcc.get_hash());
		ZaHash2 hash = ZaHash2.new_hash(config, null);
		BigInteger hash_cash_old = hash.hash2(old_cash_cert.getRoot(), this.nonce_hash_cash);
		BigInteger hash_stock_old = hash.hash2(old_stock_cert.getRoot(), this.nonce_hash_stock);
		arrInp = Utils.concat(arrInp, new BigInteger [] {
			hash_cash_old, new_cash_cert.root, 
			hash_stock_old, new_stock_cert.root,
			old_cash_cert.serial_no, old_stock_cert.serial_no
			});

		//2. arrWit for price verifier
		BigInteger [] arrWit = new BigInteger [] {};
		BigInteger [] arrWitPriceVerifier = priceVerifier.genInput(new_ts.intValue(), sid)[1];
		arrWit = Utils.concat(arrWit, arrWitPriceVerifier);

		//3. buy_decision and shares
		BigInteger share1 = old_stock_cert.q;
		BigInteger share2 = new_stock_cert.q;
		BigInteger shares = share1.compareTo(share2)>=0?
			share1.subtract(share2): share2.subtract(share1);
		BigInteger bBuy = share1.compareTo(share2)>=0?	zero: one;
		Utils.log(Utils.LOG1, "bBuy: " + bBuy + ", shares: " + shares);
		arrWit = Utils.concat(arrWit, new BigInteger [] {bBuy, shares});
		BigInteger stock_diff = bBuy.equals(one)? shares: order.subtract(shares);
		BigInteger price = arrWitPriceVerifier[2];
		BigInteger cash_diff = shares.multiply(price);
		cash_diff = bBuy.equals(one)? order.subtract(cash_diff): cash_diff;

		//4. data for cash and stock replace proof
		ZaCertReplaceVerifier zcash = new ZaCertReplaceVerifier(config,
			this.old_cash_cert, this.new_cash_cert, this.dbAcc,
			this.nonce_hash_cash, fund.fund_id, new_cash_cert.ts,
			new_cash_cert.SID, cash_diff, zg);
		BigInteger [] arrWitCash = zcash.genRandomInput(0)[1]; 
		arrWit = Utils.concat(arrWit, arrWitCash);

		

		ZaCertReplaceVerifier zstock = new ZaCertReplaceVerifier(config,
			this.old_stock_cert, this.new_stock_cert, this.dbAcc,
			this.nonce_hash_stock, fund.fund_id, new_stock_cert.ts,
			new_stock_cert.SID, stock_diff, zg);
		BigInteger [] arrWitStock = zstock.genRandomInput(0)[1]; 
		arrWit = Utils.concat(arrWit, arrWitStock);

		//5. data for encrypted instruction for broker
		ZaBrokerInstructionVerifier zb = new ZaBrokerInstructionVerifier(config, null);
		BigInteger enc_instruction = zb.logical_encode(Utils.itobi(sid), 
			shares, bBuy);
		BigInteger [][] zbinp = zb.genInput(Utils.itobi(sid), shares, bBuy, n);
		arrInp = Utils.concat(arrInp, zbinp[0]);
		arrWit = Utils.concat(arrWit, zbinp[1]);
	
		//6. return data
		return new BigInteger [][] {
			arrInp,
			arrWit
		};
	}

	// ------------------------------------------------------------------------
	// ---------------- The following are subroutinges called by local_eval ---
	// ------------------------------------------------------------------------
	/** checking if price is good */
	protected BigInteger logical_eval_checkPrice(BigInteger [] arrPubInput,
		BigInteger [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaPriceVerifier priceVerifier = new ZaPriceVerifier(config, ps, zg);
		BigInteger btrue = Utils.itobi(1);
		BigInteger bfalse = Utils.itobi(0);
		BigInteger res = btrue;

		//0. get the input data
		BigInteger [] arrwit = Utils.slice(arrWitness, 0, priceVerifier.getNumWitnessInputs());
		BigInteger ts = arrPubInput[0];
		BigInteger root_pstree = arrPubInput[1];
		BigInteger ts2 = arrwit[0];
		BigInteger root2 = arrwit[3];

		//1. check ts match
		BigInteger res1 = ts.equals(ts2)? btrue: bfalse;
		res = res.multiply(res1);

		//2. check root_pstree_match 
		BigInteger res2 = root_pstree.equals(root2)? btrue: bfalse;
		res = res.multiply(res2);

		//3. run eval on witness
		BigInteger res3 = priceVerifier.logical_eval(
			new BigInteger [] {}, arrwit)[0];
		res = res.multiply(res3);

		return res;
	}

	
	/** checking if the buy_decision and shares are valid inputs
		and retrieves price from witness
		@Return BigInteger [] - 3 elements: bOK, cash_diff and shares_diff
	*/
	protected BigInteger [] logical_eval_check_decision(BigInteger [] arrPubInput, BigInteger [] arrWitness){
		//1. retrieve buy_decision and shares, and price
		BigInteger buy_decision = arrWitness[idxBuyDecision]; 
		BigInteger shares = arrWitness[idxBuyDecision+1];
		Utils.log(Utils.LOG1, "buy_decision: " + buy_decision + 
			", shares: " + shares);
		BigInteger price = arrWitness[2]; //it's the 3'rd element in PriceProof
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);

		//2. check buy_decision is a bit
		BigInteger bOK = buy_decision.equals(one) || 
			buy_decision.equals(zero)
		? one: zero;

		//3. check shares is within 32-bit
		boolean inRange = shares.compareTo(zero)>=0 &&
			shares.compareTo(one.shiftLeft(32))<0;
		bOK = bOK.multiply(inRange? one: zero);

		//4. calculate the two differences
		BigInteger cash_diff = shares.multiply(price); //positive at this moment
		cash_diff = buy_decision.equals(one)?
			zero.subtract(cash_diff): cash_diff;
		BigInteger shares_diff = buy_decision.equals(one)?
			shares: zero.subtract(shares);

		Utils.log(Utils.LOG1, "buy_decision: " + buy_decision + 
			", shares: " + shares + ", price: " + price 
			+ ", cash_diff: " + cash_diff + ", shares_diff: " + shares_diff);

		BigInteger [] res  = new BigInteger [] {bOK, cash_diff, shares_diff};
		return res;
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

	/** check if the cash and stock replacements are performed well and
the difference in quantity matches the price * share_diff */
	protected BigInteger logical_eval_check_cert_replace(BigInteger [] arrPubInput, BigInteger [] arrWitness){
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
	}

	/** checking if broker instruction is good */
	protected BigInteger logical_eval_check_broker(BigInteger [] arrPubInput,
		BigInteger [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaBrokerInstructionVerifier zb = new ZaBrokerInstructionVerifier(config, zg);

		//0. get the input data
		BigInteger [] arrpub= Utils.slice(arrPubInput, 8+dbAcc.get_hash().length, 2); //2 64-bit words encrypted words
		BigInteger [] arrwit = Utils.slice(arrWitness, idxBroker, zb.getNumWitnessInputs());

		//2. check if it's the valid encryption using hybrid encrypt
		BigInteger res = zb.logical_eval(arrpub, arrwit)[0];
		if(res.equals(Utils.itobi(0))){
			Utils.log(Utils.LOG1, "WARNING: check_broker returns false!");
		}

		return res;
	}

	
	// ------------------------------------------------------------------------
	// ---------------- subroutines for build_circuit --------------------- ---
	// ------------------------------------------------------------------------
	/** checking if price is good */
	protected Wire build_circuit_checkPrice(Wire [] arrPubInput,
		Wire [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaPriceVerifier priceVerifier = new ZaPriceVerifier(config, ps, zg);
		Wire btrue = zg.createConstantWire(1);
		Wire bfalse = zg.createConstantWire(0);
		Wire res = btrue;

		//0. get the input data
		Wire [] arrwit = Utils.slice(arrWitness, 0, priceVerifier.getNumWitnessInputs());
		Wire ts = arrPubInput[0];
		Wire root_pstree = arrPubInput[1];
		Wire ts2 = arrwit[0];
		Wire root2 = arrwit[3];


		//1. check ts match
		res = res.and( ts.isEqualTo(ts2) );

		//2. check root_pstree_match 
		res = res.and( root_pstree.isEqualTo(root2) );

		//3. run eval on witness
		priceVerifier.build_circuit(
			new Wire [] {}, arrwit) ;
		res = res.and(priceVerifier.getOutputWires()[0]); 

		return res;
	}


	/** checking if the buy_decision and shares are valid inputs
		and retrieves price from witness
		@Return Wire [] - 3 elements: bOK, cash_diff and shares_diff
	*/
	protected Wire [] build_circuit_check_decision(Wire [] arrPubInput,
		Wire [] arrWitness){
		//1. retrieve buy_decision and shares, and price
		Wire buy_decision = arrWitness[idxBuyDecision]; 
		Wire shares = arrWitness[idxBuyDecision+1];
		Wire price = arrWitness[2]; //it's the 3'rd element in PriceProof
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		Wire one = zg.createConstantWire(1);
		Wire zero = zg.createConstantWire(0);

		//2. check buy_decision is a bit
		Wire bOK = buy_decision.isEqualTo(one).or(
			buy_decision.isEqualTo(zero)
		);

		//3. check shares is within 32-bit
		ZaRange zrp =  new ZaRange(config, 32, zg);
		zrp.build_circuit(new Wire [] {}, new Wire [] {shares});
		bOK = bOK.and(zrp.getOutputWires()[0]);

		//4. calculate the two differences
		Wire cash_diff = shares.mul(price); //positive at this moment
		cash_diff = buy_decision.mul(zero.sub(cash_diff)).
			add(one.sub(buy_decision).mul(cash_diff)); //negative for buy
		Wire shares_diff = buy_decision.mul(shares).
			add(one.sub(buy_decision).mul(zero.sub(shares))); //pos for buy

		Wire [] res  = new Wire [] {bOK, cash_diff, shares_diff};
		return res;
	}

	/** check if the cash and stock replacements are performed well and
the difference in quantity matches the price * share_diff */
	protected Wire build_circuit_check_cert_replace(Wire [] arrPubInput, Wire [] arrWitness){
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
	}

	/** checking if broker instruction is good */
	protected Wire check_broker(Wire [] arrPubInput,
		Wire [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaBrokerInstructionVerifier zb = new ZaBrokerInstructionVerifier(config, zg);

		//0. get the input data
		Wire [] arrpub= Utils.slice(arrPubInput, 8+dbAcc.get_hash().length, 2); //2 64-bit words encrypted words
		Wire [] arrwit = Utils.slice(arrWitness, idxBroker, zb.getNumWitnessInputs());

		//2. check if it's the valid encryption using hybrid encrypt
		zb.build_circuit(arrpub, arrwit);
		Wire res = zb.getOutputWires()[0];

		return res;
	}

}
