/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/10/2021
* ***************************************************/

/** **************************************************
This is the logical system of ZeroAuditServer.
It maintains a PriceServer and an accumuator
of certificate roots. All fund's and client's requests
are handled by handleRequestXYZ(ZaCirc) type of functions.

The ZaCirc's public input contains the claim/spec and
the witness part contains the secret witness. The server
calls the corresponding runAndVerify() method for each
ZaCirc to generate the proof (actually should be done
the fund's side - but we put here just for implementation convenience)
and then the logical proof is verified, then some server side
operation will be done e.g., to update certificate accumulator etc.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Hashtable;
import za_interface.za.*;
import za_interface.*;
import za_interface.za.Utils;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.accumulator.*;
import za_interface.za.circs.hash.*;

/** **************************************************
It maintains a PriceServer and an accumuator
of certificate roots. All fund's and client's requests
are handled by handleRequestXYZ(ZaCirc) type of functions.

* ***************************************************/
public class Server{
	// ** Data Members **
	/* providing price */
	protected PriceServer priceServer;
	/* stores roots of certificates */
	protected Accumulator dbCerts;  
	/* config */
	protected ZaConfig config;
	/* driver name - must match config */
	protected String driver_name;
	/* current ts */
	protected int cur_ts;
	/* database of spending ticketes (serial_nos)*/
	protected ArrayList<BigInteger> dbTickets = new ArrayList<>(); 
	/* database of asset database */
	protected Hashtable<BigInteger, Hashtable<BigInteger, BigInteger>>  dbAsset;
	/* database of purchased for each fund */
	protected Hashtable<BigInteger, Hashtable<BigInteger, BigInteger>>  dbPurchasedShares;

	// ** Operations ** 
	/** constructor */
	public Server(ZaConfig config_in, String driver_name,
		PriceServer ps, Accumulator accCerts){
		this.config = config_in;
		this.priceServer = ps;
		this.dbCerts = accCerts;
		this.cur_ts = 0;
		this.driver_name = driver_name;
		this.dbAsset = new Hashtable<BigInteger, Hashtable<BigInteger, BigInteger>>();
		this.dbPurchasedShares= new Hashtable<BigInteger, Hashtable<BigInteger, BigInteger>>();
	}

	/** throw a run time exception */	
	private void fail(String msg){
		throw new RuntimeException(msg);
	}

	protected CircuitPerfData run_circ(ZaCirc req){
		ZaDataGen.genr1cs(req);	
		String res = Utils.runR1csRunner(driver_name, config.toString(), req.getName()); 
		Utils.log(Utils.LOG1, "runR1csRunner res: " + res);
		CircuitPerfData cpd = CircuitPerfData.fromJson(res);
		Utils.log(Utils.LOG1, "runR1csRunner PerfData: " + cpd);
		if(!cpd.b_success){fail("Verification failed!");}
		return cpd;
	}

	/** handle the fund's registration request to
		register a cert root.  In req, its arrPub contains the following:
		fund_id, sid (stock_id), quantity, ts, cert_root 

		Its arrWitness has the HIDDEN secret witness, which 
		the server will NOT peek into.
		The server will call the req object to generate
		the proof, and verify proof.
	
		Additional checks to prove in a real server: if
		sid is 0 (cash), the quantity claimed should match
		the amount deposited. Otherwise will reject.

		Once proved, store the cert into the dbCert.
		If error, throws RuntimeException.
	*/
	public CircuitPerfData 
	  handleFundInitCertRequest(ZaFundInitCertVerifier req){
		//1. retrieve the public claim
		BigInteger [][] inputs = req.genRandomInput(0); //it's actually fixed
		BigInteger fund_id = inputs[0][0]; 
		BigInteger sid = inputs[0][1]; 
		BigInteger q = inputs[0][2]; 
		BigInteger ts = inputs[0][3];
		BigInteger cert_root = inputs[0][4]; 
		Utils.log(Utils.LOG2, " New Fund Cert: " + sid + ", q: " + q + ", cert_root: " + cert_root);
		if(sid.equals(Utils.itobi(0))){
			this.addFundShares(fund_id, Utils.itobi(10000), ts.intValue());
		}

		//2. perform server-side logical check
		if(!ts.equals(Utils.itobi(cur_ts))){fail("ts not matching!");}
		if(!sid.equals(Utils.itobi(0)) && !q.equals(Utils.itobi(0)))
			{fail("q is not zero!");}
		//actually there should be a check about cash, skip here

		//3. generate and verify the proof by calling the circuit 
		CircuitPerfData cpd = run_circ(req);

		//4. update the dbCerts with the new cert
		dbCerts.add_elements(new BigInteger [] {cert_root});
		return cpd;
	}

	//check if the given two values are the same
	protected void checkEq(BigInteger v, BigInteger v2, String msg){
		if(!v.equals(v2)){
			fail("Failed on: " + msg + ": v: " + v + " != v2: " + v2);
		}
	}
	
	/** handle the fund's order request.

		Its arrWitness has the HIDDEN secret witness, which 
		the server will NOT peek into, e.g., the details
		of all certs (old/new stock and cash certs), the
		sid of the stock to purchase/sell and the quantity.
		The verifier circuit guanrantees the correctness
		e.g., the account is solvable and the quqnaity change
		reflects the price etc.

		The public input of the ZaOrderVerifier circuit 
		has the information that the server have access:
		e.g., the spending ticket (serial no) of old certs,
		the commitment of the old cert and the ROOT of the new certs.
	
		Additional checks to prove in a real server: 
		check seriao_no (spending tckets) have never been used.

		Once proved, store the two new certs and the two
		spending tickets to database.

		If error, throws RuntimeException.
	*/
	public CircuitPerfData 
	  handleOrderRequest(ZaOrderVerifier req, PriceServer ps, Accumulator dbAcc, int ts){
		//1. retrieve the public claim
		BigInteger [] pi= req.genRandomInput(0)[0]; //public input
		BigInteger proof_ts =  pi[0];
		BigInteger proof_root_ps = pi[1]; 
		int dbacc_len = dbAcc.get_hash().length;
		BigInteger [] proof_root_dbAcc = Utils.slice(pi, 2, dbacc_len);
		BigInteger new_cash_root = pi[3+dbacc_len];
		BigInteger new_stock_root = pi[5+dbacc_len];
		BigInteger ticket_cash= pi[6+dbacc_len];
		BigInteger ticket_stock= pi[7+dbacc_len];
		BigInteger [] broker_instr = Utils.slice(pi, 8+dbacc_len, 2);
		

		//2. perform server-side logical check (just check the
		//			two serial_no (spending tickets);
		// and other checks
		checkEq(proof_ts, Utils.itobi(ts), "Order Req: ts");
		checkEq(proof_root_ps, ps.getRoot(ts), "Order Req: PriceServer root");
		BigInteger [] dbAcc_root = dbAcc.get_hash();
		for(int k=0; k<dbacc_len; k++) checkEq(proof_root_dbAcc[k], dbAcc_root[k], "dbAcc root: " + k);
		if(dbTickets.contains(ticket_cash)) fail("Ticket cash already used!");
		if(dbTickets.contains(ticket_stock)) fail("Ticket stock already used!");

		//3. generate and verify the proof by calling the circuit 
		CircuitPerfData cpd = run_circ(req);

		//5. update the dbCerts with the new cert
		dbAcc.add_elements(new BigInteger [] {new_cash_root, new_stock_root});
		dbTickets.add(ticket_cash);
		dbTickets.add(ticket_stock);
		return cpd;
	}

	/**
		handle the request of asserting asset raised by fund_id (to
		certify that the fund has a total asset of sumAsset at ts).
		Takes the circ for verifying holding for each stock ID and
		opening homomorphic commitment for the total . Once verified,
		will register the <fund_id, asset_value, ts> pair in database.
	*/
	public CircuitPerfData 
	  handleAssertAssetRequest(BigInteger fund_id, ZaHoldingVerifier [] req, BigInteger sumNonce, BigInteger sumAsset, PriceServer ps, Accumulator dbAcc, int ts){
		//1. get data
		Utils.log(Utils.LOG1, "Assert fund: " + fund_id + " at ts: " + ts + 
			", AssertedAsset: " + sumAsset);
		int n = req.length;
		common cm = new common();
		BigInteger [] acc_root = dbAcc.get_hash();
		BigInteger zero = Utils.itobi(0);
		BigInteger [] sumCommit = new BigInteger [] {zero, zero};
		BigInteger order = config.getFieldOrder();
		CircuitPerfData cpd = null;

		//2. process each Holding circ verifier
		for(int i=0; i<n; i++){
			//1. checking matching attributes
			BigInteger [] pi = req[i].genRandomInput(0)[0];
			cm.logical_checkVal(pi, 0, fund_id, "fundid@req" + i); 
			cm.logical_checkVal(pi, 1, Utils.itobi(i), "sid@req" + i); 
			cm.logical_checkVal(pi, 4, Utils.itobi(ts), "ts@req" + i); 
			for(int k=0; k<acc_root.length; k++){
				cm.logical_checkVal(pi,5+k,acc_root[k],"root["+k+"]@req" + i); 
			}
			BigInteger price = Utils.itobi(ps.getPrice(ts, i));
			BigInteger [] pt_shares = new BigInteger [] {pi[2], pi[3]};
			BigInteger [] pt_cur_asset = cm.pointMul(config, pt_shares[0], pt_shares[1], price);
			sumCommit = i==0? pt_cur_asset: cm.pointAdd(config, sumCommit[0], sumCommit[1], pt_cur_asset[0], pt_cur_asset[1]);

			//2. checking the cert itself
			cpd = run_circ(req[i]);
		}

		//3. verify the homomorphic commitment
		BigInteger [] com1 = cm.logical_pedersen(config, sumNonce, sumAsset);
		checkEq(com1[0], sumCommit[0], "sumCommit=perdersen(sumNonce,sumAsset)[0]");
		checkEq(com1[1], sumCommit[1], "sumCommit=perdersen(sumNonce,sumAsset)[1]");

		//4. add the pair
		this.addAssetAssertion(fund_id, sumAsset, ts);
		return cpd;
	}

	/** add the entry to db */
	public void addAssetAssertion(BigInteger fund_id, BigInteger asset, int ts){
		Utils.log(Utils.LOG1, "Adding Asset Assertion: fund: " 
			+ fund_id + ", ts: " + ts + ", asset: " + asset);
		BigInteger bts = Utils.itobi(ts);
		if(!dbAsset.containsKey(bts)){
			dbAsset.put(bts, new Hashtable<BigInteger, BigInteger>());
		}
		dbAsset.get(bts).put(fund_id, asset);
	}

	/** add the entry to db */
	public void addFundShares(BigInteger fund_id, BigInteger shares, int ts){
		Utils.log(Utils.LOG1, "Adding Fund Shares: fund: " 
			+ fund_id + ", ts: " + ts + ", shares: " + shares);
		BigInteger bts = Utils.itobi(ts);
		BigInteger curShares = getPurchasedShares(fund_id, ts);
		BigInteger newShares = curShares.add(shares);
		if(!dbPurchasedShares.containsKey(bts)){
			dbPurchasedShares.put(bts, new Hashtable<BigInteger, BigInteger>());
		}
		dbPurchasedShares.get(bts).put(fund_id, newShares);
	}

	/** return the asset value of the fund_id, assumption: the DB has
		already go a record */
	public BigInteger getAssetValue(BigInteger fund_id, int ts){
		for(; ts>=0; ts--){
			BigInteger bts = Utils.itobi(ts);
			if(dbAsset.get(bts)!=null){
				if(dbAsset.get(bts).get(fund_id)!=null){
					return dbAsset.get(Utils.itobi(ts)).get(fund_id);
				}
			}
		}	
		return null;
	}

	public BigInteger getPurchasedShares(BigInteger fund_id, int ts){
		for(; ts>=0; ts--){
			BigInteger bts = Utils.itobi(ts);
			if(dbPurchasedShares.get(bts)!=null){
				if(dbPurchasedShares.get(bts).get(fund_id)!=null){
					return dbPurchasedShares.get(Utils.itobi(ts)).get(fund_id);
				}
			}
		}	
		return Utils.itobi(10000); //default 10000 shares
	}

	/** return the NAV of the given ts. Assuming the total
	 */
	public BigInteger getNAV(BigInteger fund_id, int ts){
		BigInteger asset = getAssetValue(fund_id, ts);
		BigInteger shares = getPurchasedShares(fund_id, ts);
		BigInteger nav = asset.divide(shares);
		return nav;
	}

	/**
		Handle the request that client_id wants to buy x shares of
		fund_id at time ts, the reqInvest is generated by client_id,
		the reqDeposit is generated by fund. Once approved,
		register the claimed shares and the new two cert roots provided
		in the two proof.
	*/
	public CircuitPerfData 
	  handleInvestDepositRequest(BigInteger client_id, BigInteger fund_id, BigInteger shares, int ts, ZaInvestVerifier reqInvest, ZaDepositVerifier reqDeposit, PriceServer ps, Accumulator dbAcc){
		Utils.log(Utils.LOG1, "-- handleInvestDepositRequest --");
		//1. compute the cash_diff
		BigInteger nav = getNAV(fund_id, ts);
		BigInteger cash_diff = nav.multiply(shares);
		BigInteger bts = Utils.itobi(ts);
		int acclen = dbAcc.get_hash().length;
		BigInteger [] accroot = dbAcc.get_hash();

		//2. check all publically available attributes
		BigInteger [] ipi= reqInvest.genRandomInput(0)[0];
		BigInteger [] ipd= reqDeposit.genRandomInput(0)[0];
		BigInteger root_inv_cert = ipi[4];
		BigInteger root_cash_cert = ipd[2+accroot.length];
		if(!client_id.equals(ipi[0])) fail("client_id!=reqInvest[0]");
		if(!fund_id.equals(ipi[1])) fail("fund_id!=reqInvest[1]");
		if(!shares.equals(ipi[2])) fail("shares!=reqInvest[2]");
		if(!bts.equals(ipi[3])) fail("ts!=reqInvest[3]");
		if(!bts.equals(ipd[0])) fail("ts!=reqDeposit[0]");
		for(int k=0; k<acclen; k++){
			if(!accroot[k].equals(ipd[1+k])) fail("root[k]!=reqDeposit[dbAccroot] for k: " + k);
		}
		if(!cash_diff.equals(ipd[4+acclen])) fail("cash_diff!=reqDeposit[4+acclen]");
		if(!fund_id.equals(ipd[5+acclen])) fail("fund_id!=reqDeposit[5+acclen]");

		//3. check the reqInvest
		CircuitPerfData c1 = run_circ(reqInvest);

		//4. check the reqDeposit
		CircuitPerfData c2 = run_circ(reqDeposit);
		CircuitPerfData c3 = c1.add(c2);

		//5. update the dbCerts with the new cert
		dbCerts.add_elements(new BigInteger [] {root_inv_cert});
		dbCerts.add_elements(new BigInteger [] {root_cash_cert});
		return c3;
	}
}
