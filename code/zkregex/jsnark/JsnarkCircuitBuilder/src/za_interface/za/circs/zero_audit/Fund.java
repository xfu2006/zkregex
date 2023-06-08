/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/07/2021
* ***************************************************/

/** **************************************************
This is the logical class of a Fund.
A fund has a public fund_id which is a hash of two secret keys sk1, sk2.
It has an array of certificates (modeling the ownership of
entity 0 to n). Note that for each logical operation, such 
as register, order, and calculate asset value, there
are corresponding Za...Verifiers defined.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.accumulator.*;
import za_interface.za.Utils;


class AssertAssetRequest{
		public ZaHoldingVerifier [] arrHoldings;
		public BigInteger sumNonce;
		public BigInteger sumAsset;

		public AssertAssetRequest(ZaHoldingVerifier [] arr, BigInteger nonce,
			BigInteger asset){
			this.arrHoldings = arr;
			this.sumNonce = nonce;
			this.sumAsset = asset;
		}	
	}

/** **************************************************
This is the logical class of a Fund.
A fund has a public fund_id which is a hash of two secret keys sk1, sk2.
It has an array of certificates (modeling the ownership of
entity 0 to n). Note that for each logical operation, such 
as register, order, and calculate asset value, there
are corresponding Za...Verifiers defined.
* ***************************************************/
public class Fund{
	// ** data members **
	/** config */
	protected ZaConfig config;
	/** hash algorithm */
	protected ZaHash2 hash;
	/** secret keys */
	protected BigInteger sk1, sk2;
	/** public key of owner */
	protected BigInteger fund_id; 
	/** number of certificates */
	protected int n;
	/** array of certificates. for each index, stores the
		history and the last one is the latest, that is
		arrCerts[0] contains the history for entity 0 (cash),
		arrCerts[1] contains the history of stock 1 etc. */
	protected ArrayList<ArrayList<Cert>> arrCerts;

	/** cash is the initial cash (entity 0) and all other stocks
	ownership certificates are initialized to 0.
		n: number of stocks to generate certificate for.
		cash: initial cash;
		ts: timestamp that the fund is created. */
	public Fund(BigInteger sk1, BigInteger sk2, int n, int cash, 
			int ts, ZaConfig config){
		this.sk1 = sk1;
		this.sk2 = sk2;
		this.config = config;
		this.n = n;
		this.hash = ZaHash2.new_hash(config, null);			
		this.fund_id = this.hash.hash2(sk1, sk2);

		this.arrCerts= new ArrayList<ArrayList<Cert>>();
		for(int i=0; i<n ;i++){
			arrCerts.add(new ArrayList<Cert>());
			BigInteger q = i==0? Utils.itobi(cash): Utils.itobi(0);
			Cert cert = new Cert(fund_id, Utils.itobi(0), Utils.randbi(250), 
				Utils.itobi(i), q, Utils.itobi(ts),  config);
			arrCerts.get(i).add(cert);
		}
	}

	/** Generate a random cert.  */
	public static Fund genRandFund(int n, int nStocks, int cash, ZaConfig config){
		Random rand = new Random(n);
		BigInteger sk1 = Utils.itobi(rand.nextInt(1000000));	
		BigInteger sk2 = Utils.itobi(rand.nextInt(1000000));	
		return new Fund(
			sk1, sk2, nStocks, cash, 0, config
		);
	}

	/** get the quantity of the stock id (sid is 0) */
	public BigInteger getQ(int sid){
		ArrayList<Cert> certs = arrCerts.get(sid);
		return certs.get(certs.size()-1).q;
	}

	/** get the number of stocks */
	public int getNumStocks() {return n;}

	/** get the latest cert */
	public Cert getCert(int sid){
		ArrayList<Cert> certs = arrCerts.get(sid);
		return certs.get(certs.size()-1);
	}

	/** fail message */
	private void fail(String msg){
		throw new RuntimeException(msg);
	}

	/** Perform a buy or sell operation. If the operation is invalid,
		e.g., not sufficient cash, will throw an runtime exception.
		If ok, will generate a ZaOrderVerifier circuit */
	public ZaOrderVerifier order(int ts, int sid, int sharesToOrder, boolean buy, PriceServer ps, Accumulator dbAcc){
		//1. get the shares of cash and stock
		if(sid==0) fail("order: sid can't be cash id");	
		BigInteger shares = this.getQ(sid);
		BigInteger cash = this.getQ(0);
		BigInteger price = Utils.itobi(ps.getPrice(ts,sid));
		BigInteger sharesDiff= buy?Utils.itobi(sharesToOrder): Utils.itobi(-1*sharesToOrder);
		

		//2. based on the price calculate the new cash and new shares
		BigInteger new_cash = cash.subtract(sharesDiff.multiply(price));
		BigInteger new_shares = shares.add(sharesDiff);
		System.out.println("price: " + price);
		System.out.println( "old_cash: " + cash);
		System.out.println( "old_shares: " + shares);
		System.out.println( "new_cash: " + new_cash);
		System.out.println( "new_shares: " + new_shares);

		//3. double check
		if(new_cash.compareTo(Utils.itobi(0))<0) fail("new_cash negative!");
		if(new_shares.compareTo(Utils.itobi(0))<0) fail("new_shares negative!");
		Cert old_cash_cert = arrCerts.get(0).get(arrCerts.get(0).size()-1);
		Cert old_shares_cert = arrCerts.get(sid).get(arrCerts.get(sid).size()-1);
		if(old_cash_cert.ts.compareTo(Utils.itobi(ts))>0) fail("ts given is not right for cash, ts: " + ts + ", cert.ts: " + old_cash_cert.ts);
		if(old_shares_cert.ts.compareTo(Utils.itobi(ts))>0) fail("ts given is not right for stock, ts: " + ts + ", shares.ts: " + old_shares_cert.ts);

		//4. update the certificates
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);
		Cert new_cash_cert = new Cert(fund_id, old_cash_cert.counter.add(one),
			Utils.randbi(250),
			Utils.itobi(0), new_cash, Utils.itobi(ts), config);
		Cert new_shares_cert = new Cert(fund_id, old_shares_cert.counter.add(one),
			Utils.randbi(250),
			Utils.itobi(sid), new_shares, Utils.itobi(ts), config);
		this.arrCerts.get(0).add(new_cash_cert);
		this.arrCerts.get(sid).add(new_shares_cert);


		//5. generate the ZaOrderVerifier object
		BigInteger [] encrypted_order = null;
		ZaOrderVerifier req = new ZaOrderVerifier(config, this, 
			sid, ps, dbAcc, encrypted_order, null);
		return req;
	}

	/** return two certs such that cert1.ts <=ts and cert2.ts>ts */
	private Cert [] getCertForTs(int ts, int sid){
		BigInteger bts = Utils.itobi(ts);
		ArrayList<Cert> certs = arrCerts.get(sid);
		for(int i=0; i<certs.size()-1; i++){
			if(certs.get(i).ts.compareTo(bts)<=0 &&
				certs.get(i+1).ts.compareTo(bts)>0){
					return new Cert [] {
						certs.get(i), certs.get(i+1)
					};
			}
		}
		throw new RuntimeException("CANNOT identify consecutive certs for sid: " + sid + ", ts: " + ts);
	}

	/** Assert the asset value at the given ts. It is assumed that
		there is one cert for each stock stored to dbAcc AFTER ts 
		@return [ Array of ZaHoldingVerifier, weightedSumOfNoncesByPrice,
					weightedSumOfAsset 

		Note: weightedAsset is calculated as for each stock
			\Sigma price_i*stock_i and plus cash (with sid 1 and price 1)
	*/
	public AssertAssetRequest assertAsset(int ts, PriceServer ps, Accumulator dbAcc){
		//1. data
		BigInteger sumNonce = Utils.itobi(0);
		BigInteger sumAsset = Utils.itobi(0);
		ZaHoldingVerifier [] arrHolding = new ZaHoldingVerifier [n];
		BigInteger order = config.getFieldOrder();

		//2. do it for each stock
		for(int sid=0; sid<n; sid++){
			Cert [] certs = getCertForTs(ts, sid);
			BigInteger shares = certs[0].q;
			BigInteger price = Utils.itobi(ps.getPrice(ts, sid));
			arrHolding[sid] = new ZaHoldingVerifier(config, certs[0], certs[1],
				Utils.itobi(ts), dbAcc, null);
			BigInteger nonce = arrHolding[sid].genRandomInput(0)[1][0];
			sumAsset = sumAsset.add(shares.multiply(price)).mod(order);
			sumNonce = sumNonce.add(nonce.multiply(price)).mod(order);
		}

		//3. return
		return new AssertAssetRequest(arrHolding, sumNonce, sumAsset);
	}

	/** Perform a Deposit operation */
	public ZaDepositVerifier deposit(int ts, BigInteger cash_diff, PriceServer ps, Accumulator dbAcc){
		//1. get the shares of cash and stock
		if(cash_diff.compareTo(Utils.itobi(0))<0) fail("cash_diff is neg!");
		if(cash_diff.compareTo(Utils.itobi(1).shiftLeft(64))>0) fail("cash_diff too big!");
		BigInteger cash = this.getQ(0);
		BigInteger new_cash = cash.add(cash_diff);
		if(new_cash.compareTo(Utils.itobi(1).shiftLeft(64))>0) fail("cash_diff too big!");
		Cert old_cash_cert = arrCerts.get(0).get(arrCerts.get(0).size()-1);
		if(old_cash_cert.ts.compareTo(Utils.itobi(ts))>0) fail("ts given is not right for cash, ts: " + ts + ", cert.ts: " + old_cash_cert.ts);

		//2. update the certificates
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);
		Cert new_cash_cert = new Cert(fund_id, old_cash_cert.counter.add(one),
			Utils.randbi(250),
			Utils.itobi(0), new_cash, Utils.itobi(ts), config);
		this.arrCerts.get(0).add(new_cash_cert);


		//3. generate the ZaDepositVerifier object
		ZaDepositVerifier req = new ZaDepositVerifier(config, this, 
			ps, dbAcc, null);
		return req;
	}

}
