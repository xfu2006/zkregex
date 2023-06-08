/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/20/2021
* ***************************************************/

/** **************************************************
Random tests for each circuit
* ***************************************************/
package za_interface.za.circs.tests;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.Before;
import org.junit.Assert;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import java.util.ArrayList;
import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.Utils;

import za_interface.za.circs.basicops.*;
import za_interface.za.circs.hash.sha.*;
import za_interface.za.circs.hash.pedersen.*;
import za_interface.za.circs.commit.*;
import za_interface.za.circs.curve.*;
import za_interface.za.circs.exchange.*;
import za_interface.za.circs.encrypt.block.*;
import za_interface.za.circs.encrypt.pubkey.*;
import za_interface.za.circs.encrypt.hybrid.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.range.*;
import za_interface.za.circs.zkreg.*;
import za_interface.za.circs.zero_audit.*;


public class RandTest extends TestCase {
	private final PrintStream stdout = System.out;
	private final ByteArrayOutputStream os = new ByteArrayOutputStream();
	private int TIMES = 10;

	@Before
	public void setupBeforeClass(){
/** Enable the following for detailed output */
		System.setOut(new PrintStream(os));
		Utils.setLogLevel(Utils.LOG3);
	}

/*
	@Test
	public void testRandAdd() {
		Utils.log(Utils.WARN, "randtest Add");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaAdd = new ZaAdd(arrc.get(k), null);
			CircTester.testCirc(zaAdd,i);	
		  }
		}
	}
	@Test
	public void testRandRSA() {
		Utils.log(Utils.WARN, "randtest RSA");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaRSA = new ZaRSA(arrc.get(k), null);
			CircTester.testCirc(zaRSA,i);	
		  }
	  	}
	}

	@Test
	public void testRandSha2() {
		Utils.log(Utils.WARN, "randtest Sha2");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaSha2 = new ZaSha2(arrc.get(k), null);
			CircTester.testCirc(zaSha2,i);	
		  }
	  	}
	}


	@Test
	public void testRandSplit() {
		Utils.log(Utils.WARN, "randtest Split");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaSplit = new ZaSplit(arrc.get(k), 256, null);
			CircTester.testCirc(zaSplit,i);	
		  }
		}
	}

	@Test
	public void testRandSha2Path() {
		Utils.log(Utils.WARN, "randtest Sha2Path");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaSha2Path = new ZaSha2Path(arrc.get(k), 10, null);
			CircTester.testCirc(zaSha2Path,i);	
		  }
		}
	}

	@Test
	public void testRandHashCommit() {
		Utils.log(Utils.WARN, "randtest HashCommit");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaCirc zaHashCommit = new ZaHashCommit(arrc.get(k), null);
				CircTester.testCirc(zaHashCommit,i);	
			}
		}
	}

	@Test
	public void testRandSameCommit() {
		Utils.log(Utils.WARN, "randtest SameCommit");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaCirc zaSameCommit = new ZaSameCommit(arrc.get(k), null);
				CircTester.testCirc(zaSameCommit,i);	
			}
		}
	}

	@Test
	public void testRandZaComputeY() {
		Utils.log(Utils.WARN, "randtest ZaComputeY");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				Curve curve = Curve.createCurve(arrc.get(k));
				ZaCirc zaZaComputeY = new ZaComputeY(curve, null);
				CircTester.testCirc(zaZaComputeY,i);	
			}
		}
	}

	@Test
	public void testRandZaPointAdd() {
		Utils.log(Utils.WARN, "randtest ZaPointAdd");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				Curve curve = Curve.createCurve(arrc.get(k));
				ZaCirc zaZaPointAdd = new ZaPointAdd(curve, null);
				CircTester.testCirc(zaZaPointAdd,i);	
			}
		}
	}

	@Test
	public void testRandZaPointDouble() {
		Utils.log(Utils.WARN, "randtest ZaPointDouble");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				Curve curve = Curve.createCurve(arrc.get(k));
				ZaCirc zaZaPointDouble = new ZaPointDouble(curve, null);
				CircTester.testCirc(zaZaPointDouble,i);	
			}
		}
	}

	@Test
	public void testRandZaPointMul() {
		Utils.log(Utils.WARN, "randtest ZaPointMul");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				Curve curve = Curve.createCurve(arrc.get(k));
				ZaCirc zaZaPointMul = new ZaPointMul(curve, null);
				CircTester.testCirc(zaZaPointMul,i);	
			}
		}
	}

	@Test
	public void testRandZaPedersen() {
		Utils.log(Utils.WARN, "randtest ZaPedersen");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				if(config.hash_alg!=ZaConfig.EnumHashAlg.Pedersen) continue;
				ZaCirc zaZaPedersen = new ZaPedersen(config, null);
				CircTester.testCirc(zaZaPedersen,i);	
			}
		}
	}

	@Test
	public void testRandZaECDH() {
		Utils.log(Utils.WARN, "randtest ZaECDH");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaCirc zaZaECDH = new ZaECDH(config, null);
				CircTester.testCirc(zaZaECDH,i);	
			}
		}
	}
	@Test
	public void testRandZaSpeck128() {
		Utils.log(Utils.WARN, "randtest ZaSpeck128");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaCirc zaZaSpeck128 = new ZaSpeck128(config, null);
				CircTester.testCirc(zaZaSpeck128,i);	
			}
		}
	}

	@Test
	public void testRandZaCBCSpeck() {
		Utils.log(Utils.WARN, "randtest ZaCBCSpeck");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaCirc zaZaCBCSpeck = new ZaCBCSpeck(config, 1020, null);
				CircTester.testCirc(zaZaCBCSpeck,i);	
			}
		}
	}

	@Test
	public void testRandZaHybridDHSpeck() {
		Utils.log(Utils.WARN, "randtest ZaHybridDHSpeck");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaCirc zaZaHybridDHSpeck = new ZaHybridDHSpeck(config, 1020, null);
				CircTester.testCirc(zaZaHybridDHSpeck,i);	
			}
		}
	}

	@Test
	public void testRandZaMerkleAccVerifier() {
		Utils.log(Utils.WARN, "randtest ZaMerkleAccVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				MerkleAccumulator ma = MerkleAccumulator.create(10, config, null);
				ZaCirc zaVer= ma.genVerifier();
				CircTester.testCirc(zaVer,i);	
			}
		}
	}

	@Test
	public void testRandZaRange() {
		Utils.log(Utils.WARN, "randtest ZaRange");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaCirc zaRange = new ZaRange(config, 10, null);
				CircTester.testCirc(zaRange,i);	
			}
		}
	}


	@Test
	public void testRandZaCertVerifier() {
		Utils.log(Utils.WARN, "randtest ZaCertVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				Cert cert = Cert.genRandCert(i, config);
				ZaCirc zaCertVerifier = new ZaCertVerifier(config, cert, null);
				CircTester.testCirc(zaCertVerifier,i);	
			}
		}
	}

	@Test
	public void testRandZaPriceVerifier() {
		Utils.log(Utils.WARN, "randtest ZaPriceVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				PriceServer ps = PriceServer.create(4, 4, config, null);
				ZaPriceVerifier zaVerify= new ZaPriceVerifier(config, ps, null);
				CircTester.testCirc(zaVerify,i);	
			}
		}
	}


	@Test
	public void testRandZaFundInitCertVerifier() {
		Utils.log(Utils.WARN, "randtest ZaFundInitCertVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				Fund fund = Fund.genRandFund(i, 4, 999999999, config);
				ZaFundInitCertVerifier zaVerify= new ZaFundInitCertVerifier(config, fund, 2, null);
				CircTester.testCirc(zaVerify,i);	
			}
		}
	}

	@Test
	public void testRandZaBrokerInstructionVerifier() {
		Utils.log(Utils.WARN, "randtest ZaBrokerInstructionVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				ZaBrokerInstructionVerifier zaVerify= new ZaBrokerInstructionVerifier(config, null);
				CircTester.testCirc(zaVerify,i);	
			}
		}
	}

	@Test
	public void testRandZaOrderVerifier() {
		Utils.log(Utils.WARN, "randtest ZaOrderVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int n=0; n<arrc.size(); n++){
			TIMES = 1;
			ZaConfig config = arrc.get(n);
			  for(int u=0; u<TIMES; u++){
				Utils.log(Utils.WARN, "testOrderVerifier");
				//ZaConfig config = ZaConfig.defaultConfig();
				Utils.log(Utils.LOG2, " -- create price server");
				PriceServer ps = PriceServer.create(4, 4, config, null);
				Utils.log(Utils.LOG2, " -- gen fund");
				Fund fund = Fund.genRandFund(2, 3, 900000000, config);
				Utils.log(Utils.LOG2, " -- create acc");
				MerkleAccumulator dbAcc= MerkleAccumulator.create(10, config, null);
				Utils.log(Utils.LOG2, " -- add funds's cert");
				for(int i=0; i<fund.getNumStocks(); i++){
					dbAcc.add_elements(new BigInteger [] {fund.getCert(i).getRoot()});
				}
				//buy/sell 10 shares of shares
			    int ts = 1;
				for(int k=0; k<2; k++){
					boolean bBuy = k%2==0;
					Utils.log(Utils.LOG2, " --  buy op");
					int sid = 1;
					ZaOrderVerifier zaVerify= fund.order(ts, sid, 10, bBuy, ps, dbAcc);
					BigInteger bres = CircTester.testCirc(zaVerify,u)[0];	
					if(!bres.equals(Utils.itobi(1))){
						Assert.fail("Order verification fails returns 0!");
					}
					//simulate the addition of two cert roots
					BigInteger new_cash_root = fund.getCert(0).getRoot();
					BigInteger new_stock_root = fund.getCert(sid).getRoot();
					dbAcc.add_elements(new BigInteger[] {new_cash_root, new_stock_root});
					ts++;
				}
			  }
		}
	}



	@Test
	public void testRandZaHoldingVerifier() {
		Utils.log(Utils.WARN, "randtest ZaHoldingVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int u=0; u<TIMES; u++){
				Utils.log(Utils.WARN, "testHoldingVerifier");
				ZaConfig config = arrc.get(k);
				MerkleAccumulator dbAcc= MerkleAccumulator.create(10, config, null);
				BigInteger pk = Utils.itobi(100);
				BigInteger counter = Utils.itobi(200);
				BigInteger nonce = Utils.randbi(250);
				BigInteger SID = Utils.itobi(200);
				BigInteger ts = Utils.itobi(1000);
				BigInteger ts2 = Utils.itobi(2001);
				BigInteger q = Utils.randbi(50);
				BigInteger q2 = Utils.randbi(51);
				BigInteger order = config.getFieldOrder();
				BigInteger q_diff = (q2.subtract(q).add(order)).mod(order);
				Cert cert1= new Cert(pk, counter, nonce, SID, q, ts, config);
				dbAcc.add_elements(new BigInteger [] {cert1.getRoot()});
				BigInteger counter2 = counter.add(Utils.itobi(1));
				if(u%2==1){//introduce an error
					counter2 = counter2.add(Utils.itobi(1));
				}
				BigInteger nonce_hash = Utils.randbi(200);
				Cert cert2= new Cert(pk, counter2, nonce, SID, q2, ts2, config);
				dbAcc.add_elements(new BigInteger [] {cert2.getRoot()});
				ZaHoldingVerifier zaVerify= new ZaHoldingVerifier(config, cert1, cert2, ts, dbAcc,  null);
				BigInteger bres = CircTester.testCirc(zaVerify,u)[0];	
				if(!bres.equals(Utils.itobi(1)) && u%2==0){
					Assert.fail("Order verification fails returns 0!");
				}
			  }
		}
	}

	@Test
	public void testRandZaInvestVerifier() {
		Utils.log(Utils.WARN, "randtest ZaInvestVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
			for(int i=0; i<TIMES; i++){
				ZaConfig config = arrc.get(k);
				Client client = Client.genRandClient(config);
				Cert cert = Cert.genRandCert(i, config);
				ZaCirc zaInvestVerifier = new ZaInvestVerifier(config, client, cert, null);
				CircTester.testCirc(zaInvestVerifier,i);	
			}
		}
	}

	@Test
	public void testRandZaOrderVerifier() {
		Utils.log(Utils.WARN, "randtest ZaOrderVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int n=0; n<arrc.size(); n++){
			Utils.log(Utils.WARN, "testDepositVerifier");
			ZaConfig config = arrc.get(n);
			Utils.log(Utils.LOG2, "create price server");
			PriceServer ps = PriceServer.create(4, 10, config, null);
			Utils.log(Utils.LOG2, " -- gen fund");
			Fund fund = Fund.genRandFund(2, 3, 900000000, config);
			Utils.log(Utils.LOG2, " -- create acc");
			MerkleAccumulator dbAcc= MerkleAccumulator.create(10, config, null);
			Utils.log(Utils.LOG2, " -- add funds's cert");
			for(int i=0; i<fund.getNumStocks(); i++){
				dbAcc.add_elements(new BigInteger [] {fund.getCert(i).getRoot()});
			}
		    int ts = 1;
			BigInteger cash_diff = Utils.itobi(90000);
			ZaDepositVerifier zaVerify= fund.deposit(ts, cash_diff , ps, dbAcc);
			BigInteger bres = CircTester.testCirc(zaVerify,n)[0];	
			if(!bres.equals(Utils.itobi(1))){
				Assert.fail("Deposit verification fails returns 0!");
			}
		}
	}
	@Test
	public void testRandPow() {
		Utils.log(Utils.WARN, "randtest Pow");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			ZaCirc zaPow = new ZaPow(arrc.get(k), null, 4);
			CircTester.testCirc(zaPow,i);	
		  }
	  	}
	}
*/
	@Test
	public void testRandTraceVerifier() {
		Utils.log(Utils.WARN, "randtest TraceVerifier");
		ArrayList<ZaConfig> arrc = ZaConfig.enumAllZaConfigs();
		for(int k=0; k<arrc.size(); k++){
		  for(int i=0; i<TIMES; i++){
			//128 input chars, state bitwidth is 20-bits
			ZaCirc zaTraceVerifier = new ZaTraceVerifier(arrc.get(k), null, 128, 20);
			CircTester.testCirc(zaTraceVerifier,i);	
		  }
	  	}
	}

}
