/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/24/2021
* ***************************************************/

/** **************************************************
This is the logical system of system. It has the main()
function that simulates the running of the zero_audit
interaction of client, fund, and (ZeroAudit) server.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import za_interface.za.ZaConfig;
import za_interface.za.Utils;
import za_interface.za.circs.zero_audit.*;
import za_interface.ZaDataGen;
import za_interface.PrimeFieldInfo;
import za_interface.za.circs.accumulator.*;
import za_interface.za.circs.accumulator.merkle.*;

/** **************************************************
This is the logical system of system. It has the main()
function that simulates the running of the zero_audit
interaction of client, fund, and server.
* ***************************************************/
public class CompositeSystem{
	// ** data members **
	public static String AURORA_EXEC = "AuroraExec";
	public static String SpartanNizkDriver= "SpartanNizkDriver";
	
	// ** Operations **
	/**
		@param rounds - how many rounds of transaction
		@param nStocksByFund -how many stocks owned by fund
		@param nDays - how many days in price tree
		@param log2stocks - in price tree, the number of stocks to support
		@param log2acc - the log2 of the capacity of database of certs
		
	*/
	public static void run(ZaConfig config, String driver_name, int rounds,
		int nStocksByFund, int nDays, int log2stocks, int log2acc){
		Utils.log(Utils.LOG1, "Run with config: " + config);

		//1. create fund and register it
		Utils.log(Utils.LOG1, "Creating price server ...");
		PriceServer ps = PriceServer.create(nDays, log2stocks, config, null);
		Utils.log(Utils.LOG1, "Creating cert accumulator ...");
		MerkleAccumulator acc = MerkleAccumulator.create(log2acc, config, null);
		Utils.log(Utils.LOG1, "Creating server...");
		Server server = new Server(config, driver_name, ps, acc);  
		Utils.log(Utils.LOG1, "Creating Fund...");
		int initCash = 100000000;
		Fund fund = Fund.genRandFund(0, nStocksByFund, initCash, config);
		for(int i=0; i<nStocksByFund; i++){
			Utils.log(Utils.LOG1, "Handle Init Cert Request: " + i + "...");
			ZaFundInitCertVerifier req = new ZaFundInitCertVerifier(config, fund, i, null);
			server.handleFundInitCertRequest(req);
		}
		server.addAssetAssertion(fund.fund_id, Utils.itobi(initCash), 0); 
		Utils.log(Utils.LOG1, "Creating Client ...");
		Client client = Client.genRandClient(config); 

		//2. Do a couple of fund buy/sell/invest and assert for each ts
		int ts = 1;
		for(int i=0; i<rounds; i++){
			//2.1 buy sell
			if(i%3!=2){
				boolean bBuy = i%2==0;	
				for(int sid = 1; sid<nStocksByFund; sid++){
					Utils.log(Utils.LOG1, "Round: " + i + ", buy: " + bBuy);
					ZaOrderVerifier zo= fund.order(ts, sid, 10-sid, bBuy, ps, acc);
					CircuitPerfData cpd = server.handleOrderRequest(zo, ps, acc, ts);
				}
			}else{//invest when i%3==0
				BigInteger bts = Utils.itobi(ts);
				BigInteger nav = server.getNAV(fund.fund_id, ts);
				BigInteger shares = Utils.itobi(10);
				BigInteger cash_diff = nav.multiply(shares);
				ZaInvestVerifier zi = client.invest(fund.fund_id, shares, ts);
				ZaDepositVerifier zd = fund.deposit(ts, cash_diff, ps, acc);
				server.handleInvestDepositRequest(client.client_id, fund.fund_id, shares, ts, zi, zd, ps, acc);
			}
			ts ++;

			//2.2 assert assets
			AssertAssetRequest req = fund.assertAsset(ts-2, ps, acc);	
			CircuitPerfData cpdAssert = 
				server.handleAssertAssetRequest(fund.fund_id,
					req.arrHoldings, req.sumNonce, req.sumAsset, ps, acc, ts-2);
		}
	}
	
	public static void main(String [] args){
		Utils.setLogLevel(Utils.LOG2);
		Utils.log(Utils.LOG1, "ZeroAUDIT_R1CS CompositeSystem Running");
		ZaConfig config = ZaConfig.defaultConfig();
		config.field_info = PrimeFieldInfo.AURORA;
		String driver_name = AURORA_EXEC;
		run(config, driver_name, 
			1,  //rounds of order transactions
			3, //nStocks owned by a fund
			4, //ndays in price tree
			10, //log of capacity of price tree
			10 //log of capacity of cert accumulator
		);
	}
}
