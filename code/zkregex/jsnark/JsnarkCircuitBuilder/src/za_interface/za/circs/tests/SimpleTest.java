/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/20/2021
* ***************************************************/

/** **************************************************
Simple Test (just generate simple case input 0)
* ***************************************************/
package za_interface.za.circs.tests;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Assert;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.Utils;

import za_interface.za.circs.basicops.*;
import za_interface.za.circs.hash.sha.*;
import za_interface.za.circs.hash.poseidon.*;
import za_interface.za.circs.hash.pedersen.*;
import za_interface.za.circs.hash.mimc.*;
import za_interface.za.circs.exchange.*;
import za_interface.za.circs.commit.*;
import za_interface.za.circs.curve.*;
import za_interface.za.circs.encrypt.block.*;
import za_interface.za.circs.encrypt.pubkey.*;
import za_interface.za.circs.encrypt.hybrid.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.range.*;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.zkreg.*;
import za_interface.za.*;
import za_interface.*;

import cs.Employer.ac.AC; 
/** 
  provides class for running one functional test
*/
class CircTester{
	protected boolean iseq(BigInteger [] a, BigInteger [] b){
		if(a.length!=b.length){
			Utils.log(Utils.LOG1, "iseq false: a.length: " 
				+ a.length + ", b.length: " + b.length);
			return false;
		}
		for(int i=0; i<a.length; i++){
			if(!a[i].equals(b[i])){
				Utils.log(Utils.LOG1, "iseq false at index: "
					+ i + ", a[i]: "
					+ a[i] + ", b[i]: " + b[i]);
				return false;
			}
		}
		return false;
	}
	/**
		Call circ's genRandomInput(n) and feed the input.
		Test if the logical_eval() matches eval()
	*/
	public static BigInteger [] testCirc(ZaCirc circ, int n){
		Utils.log(Utils.WARN, "Test i: " + n + ", circ: " + circ.getName() + ", config: " + circ.getConfig());
		System.out.println(" *** Test i: " + n + ", circ: " + circ.getName() + ", config: " + circ.getConfig());
		

		//1. generate the random input
		BigInteger [][] inputs = circ.genRandomInput(n);

		//2. run the logical eval
		BigInteger [] resLogic = circ.logical_eval(inputs[0], inputs[1]);

		//3. run the real eval
		BigInteger [] resReal = circ.eval(inputs[0], inputs[1]);

		//4. compare result
		//for(int i=0; i<resLogic.length; i++){
		for(int i=0; i<2 && i<resLogic.length; i++){
			Utils.log(Utils.LOG2, "resLogic[" + i + "]: " + resLogic[i] + 
				", resReal[" + i + "]: " + resReal[i]);
		}
		Assert.assertArrayEquals(resLogic, resReal);
		return resLogic;
	}
}

public class SimpleTest extends TestCase {
	private final PrintStream stdout = System.out;
	private final ByteArrayOutputStream os = new ByteArrayOutputStream();

	@BeforeClass
	public void setUp(){
		//System.setOut(new PrintStream(os));
		Utils.setLogLevel(Utils.LOG3);
	}

/*	
	@Test
	public void testAdd() {
		Utils.log(Utils.WARN, "testAdd");
		ZaCirc zaAdd = new ZaAdd(ZaConfig.defaultConfig(), null);
		CircTester.testCirc(zaAdd,0);	
	}

	@Test
	public void testSplit() {
		Utils.log(Utils.WARN, "testSplit");
		ZaCirc zaSplit= new ZaSplit(ZaConfig.defaultConfig(), 256, null);
		CircTester.testCirc(zaSplit,0);	
	}

	@Test
	public void testSha2() {
		Utils.log(Utils.WARN, "testSha2");
		ZaCirc zaSha2= new ZaSha2(ZaConfig.defaultConfig(), null);
		CircTester.testCirc(zaSha2,0);	
	}

	@Test
	public void testRSA() {
		Utils.log(Utils.WARN, "testRSA");
		ZaCirc zaRSA= new ZaRSA(ZaConfig.defaultConfig(), null);
		CircTester.testCirc(zaRSA,0);	
	}

	@Test
	public void testSha2Path() {
		Utils.log(Utils.WARN, "testSha2Path");
		ZaCirc zaSha2Path= new ZaSha2Path(ZaConfig.defaultConfig(), 10, null);
		CircTester.testCirc(zaSha2Path,0);	
	}

	@Test
	public void testHashCommit() {
		Utils.log(Utils.WARN, "testHashCommit");
		ZaCirc zaHashCommit= new ZaHashCommit(ZaConfig.defaultConfig(), null);
		CircTester.testCirc(zaHashCommit,0);	
	}

	@Test
	public void testSameCommit() {
		Utils.log(Utils.WARN, "testSameCommit");
		ZaCirc zaSameCommit= new ZaSameCommit(ZaConfig.defaultConfig(), null);
		CircTester.testCirc(zaSameCommit,0);	
	}
	@Test
	public void testZaComputeY() {
		Utils.log(Utils.WARN, "testZaComputeY");
		Curve curve = Curve.createCurve(ZaConfig.defaultConfig());
		ZaCirc zaComputeY = new ZaComputeY(curve, null);
		CircTester.testCirc(zaComputeY,0);	
	}

	@Test
	public void testZaPointAdd() {
		Utils.log(Utils.WARN, "testZaPointAdd");
		Curve curve = Curve.createCurve(ZaConfig.defaultConfig());
		ZaCirc zaPointAdd = new ZaPointAdd(curve, null);
		CircTester.testCirc(zaPointAdd,0);	
	}

	@Test
	public void testZaPointDouble() {
		Utils.log(Utils.WARN, "testZaPointDouble");
		Curve curve = Curve.createCurve(ZaConfig.defaultConfig());
		ZaCirc zaPointDouble = new ZaPointDouble(curve, null);
		CircTester.testCirc(zaPointDouble,0);	
	}

	@Test
	public void testZaPointMul() {
		Utils.log(Utils.WARN, "testZaPointMul");
		Curve curve = Curve.createCurve(ZaConfig.defaultConfig());
		ZaCirc zaPointMul = new ZaPointMul(curve, null);
		CircTester.testCirc(zaPointMul,0);	
	}

	@Test
	public void testPedersen() {
		Utils.log(Utils.WARN, "testPedersen");
		ZaConfig config = ZaConfig.defaultConfig();
		config.hash_alg  = ZaConfig.EnumHashAlg.Pedersen;
		ZaCirc zaPedersen= new ZaPedersen(config, null);
		CircTester.testCirc(zaPedersen,0);	
	}

	@Test
	public void testECDH() {
		Utils.log(Utils.WARN, "testECDH");
		ZaConfig config = ZaConfig.defaultConfig();
		ZaCirc zaECDH= new ZaECDH(config, null);
		CircTester.testCirc(zaECDH,0);	
	}

	@Test
	public void testSpeck128() {
		Utils.log(Utils.WARN, "testSpeck128");
		ZaConfig config = ZaConfig.defaultConfig();
		ZaCirc zaSpeck128= new ZaSpeck128(config, null);
		CircTester.testCirc(zaSpeck128,0);	
	}

	@Test
	public void testCBCSpeck() {
		Utils.log(Utils.WARN, "testCBCSpeck");
		ZaConfig config = ZaConfig.defaultConfig();
		ZaCirc zaCBCSpeck= new ZaCBCSpeck(config, 237, null);
		CircTester.testCirc(zaCBCSpeck,0);	
	}

	@Test
	public void testHybridDHSpeck() {
		Utils.log(Utils.WARN, "testHybridDHSpeck");
		ZaConfig config = ZaConfig.defaultConfig();
		ZaCirc zaHybridZDSpeck= new ZaHybridDHSpeck(config, 237, null);
		CircTester.testCirc(zaHybridZDSpeck,0);	
	}

	@Test
	public void testMerkleAccVerifier() {
		Utils.log(Utils.WARN, "testMerkleAccVerifier");
		ZaConfig config = ZaConfig.defaultConfig();
		MerkleAccumulator ma = MerkleAccumulator.create(10, config, null);
		ZaCirc zaVerify= ma.genVerifier();
		CircTester.testCirc(zaVerify,0);	
	}
	@Test
	public void testRange() {
		Utils.log(Utils.WARN, "testRange");
		ZaConfig config = ZaConfig.defaultConfig();
		ZaCirc zaRange= new ZaRange(config, 64, null); //64-bit range
		CircTester.testCirc(zaRange,0);	
	}

	@Test
	public void testCertVerifier() {
		Utils.log(Utils.WARN, "testCertVerifier");
		ZaConfig config = ZaConfig.defaultConfig();
		Cert cert= Cert.genRandCert(10, config);
		ZaCirc zaVerify= new ZaCertVerifier(config, cert, null);
		CircTester.testCirc(zaVerify,0);	
	}


	@Test
	public void testPriceVerifier() {
	  for(int u=0; u<15; u++){
     	System.out.println(" === test round: ===" + u);
		Utils.log(Utils.WARN, "testPriceVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
		PriceServer ps = PriceServer.create(2, 4, config, null);
		ZaPriceVerifier zaVerify= new ZaPriceVerifier(config, ps, null);
		CircTester.testCirc(zaVerify,1);	
	  }
	}

	@Test
	public void testFundInitCertVerifier() {
	  for(int u=0; u<2; u++){
		Utils.log(Utils.WARN, "testFundInitCertVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
		Fund fund = Fund.genRandFund(u, 3, 90000000, config);
		ZaFundInitCertVerifier zaVerify= new ZaFundInitCertVerifier(config, fund, 2, null);
		CircTester.testCirc(zaVerify,u);	
	  }
	}

	@Test
	public void testCertReplaceVerifier() {
	  for(int u=0; u<2; u++){
		Utils.log(Utils.WARN, "testCertReplaceVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
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
		ZaCertReplaceVerifier zaVerify= new ZaCertReplaceVerifier(config, cert1, cert2, dbAcc, nonce_hash, pk, ts2, SID, q_diff, null);
		BigInteger bres = CircTester.testCirc(zaVerify,u)[0];	
		if(!bres.equals(Utils.itobi(1)) && u%2==0){
			Assert.fail("Order verification fails returns 0!");
		}
	  }
	}

	@Test
	public void testBrokerInstructionVerifier() {
	  for(int u=0; u<5; u++){
     	System.out.println(" === test round: ===" + u);
		Utils.log(Utils.WARN, "testBrokerInstructionVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
		ZaBrokerInstructionVerifier zaVerify= new ZaBrokerInstructionVerifier(config, null);
		CircTester.testCirc(zaVerify,1);	
	  }
	}

	@Test
	public void testOrderVerifier() {
	  for(int u=0; u<2; u++){
		Utils.log(Utils.WARN, "testOrderVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Sha); 
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
		//buy/sell 10 shares of shares
	    int ts = 1;
		for(int k=0; k<2; k++){
			boolean bBuy = k%2==0;
			Utils.log(Utils.LOG3, " -- buy op");
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

	@Test
	public void testHoldingVerifier() {
	  for(int u=0; u<2; u++){
		Utils.log(Utils.WARN, "testHoldingVerifier");
		//ZaConfig config = ZaConfig.defaultConfig();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
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
			Assert.fail("Stock Holding verification fails returns 0!");
		}
	  }
	}

*/


/*
	//generate two certs
    private Cert [] genTwoCerts(ZaConfig config, int sid, int [] shares){
		//1. generate the ZaHoldingVerify circ
		BigInteger pk = Utils.itobi(100);
		BigInteger counter = Utils.itobi(200);
		BigInteger nonce = Utils.randbi(250);
		BigInteger SID = Utils.itobi(sid);
		BigInteger ts = Utils.itobi(0);
		BigInteger ts2 = Utils.itobi(1);
		BigInteger q = Utils.itobi(shares[sid]);
		BigInteger q2 = Utils.randbi(20);
		BigInteger order = config.getFieldOrder();
		BigInteger counter2 = counter.add(Utils.itobi(1));
		Cert cert1= new Cert(pk, counter, nonce, SID, q, ts, config);
		Cert cert2= new Cert(pk, counter2, nonce, SID, q2, ts2, config);
		return new Cert [] {cert1, cert2};
	}

	//just print a vec of two numbers
	private void print_vec(String msg, BigInteger [] vec){
		System.out.println(msg + ": " + vec[0] + ", " + vec[1]);
	}
	@Test
	public void testAssertAsset() {
		common cm = new common();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 

		//1. prepare the price server and constants
		Utils.log(Utils.LOG2, "create price server ...");
		int numStocks = 2;
		PriceServer ps = PriceServer.create(3, numStocks, config, null);
		int [] init_shares = new int [numStocks];
		for(int i=0; i<numStocks; i++) init_shares[i] = i+10;	
		Curve curve = cm.newCurve(config);
		BigInteger sb_order = curve.subgroup_order;
		BigInteger zero = Utils.itobi(0);

		//2. declare the variables for loop
		BigInteger nonce = zero;
		BigInteger prf_cur_asset_commit = zero;
		BigInteger  prf_total_asset_commit = zero;
		BigInteger [] prf_pt_total_asset_commit = null;
		BigInteger logical_cur_asset = zero;
		BigInteger logical_cur_asset_commit = zero;
		BigInteger logical_total_nonce = zero;
		BigInteger logical_total_asset = zero;
		BigInteger logical_total_asset_commit = zero;
		

		//2. loop
		for(int sid=0; sid<numStocks; sid++){
			//2.1 generate the certs and verifier objects 
			MerkleAccumulator dbAcc= MerkleAccumulator.create(10, config, null);
			Cert [] certs = genTwoCerts(config, sid, init_shares);
			Cert cert1 = certs[0]; Cert cert2 = certs[1];
			dbAcc.add_elements(new BigInteger [] {cert1.getRoot()});
			dbAcc.add_elements(new BigInteger [] {cert2.getRoot()});
			ZaHoldingVerifier zaVerify= new ZaHoldingVerifier(config, cert1, cert2, Utils.itobi(0), dbAcc,	null);
			BigInteger [] pi = zaVerify.genRandomInput(0)[0];
			BigInteger [] aw = zaVerify.genRandomInput(0)[1];

			//2.2 update the homomorphic sum on the logical side
			BigInteger shares = cert1.getQ();
			BigInteger price = Utils.itobi(ps.getPrice(0, sid));
			nonce = aw[0];
			BigInteger nonce_price = nonce.multiply(price).mod(sb_order);		
			logical_total_nonce = logical_total_nonce.add(nonce_price).mod(sb_order);
			logical_cur_asset = shares.multiply(price).mod(sb_order);
			logical_total_asset = logical_total_asset.add(logical_cur_asset).mod(sb_order);
			logical_cur_asset_commit = cm.pedersen(config, nonce_price, shares);
			BigInteger [] logical_pt_cur_asset_commit = cm.xToPoint(config, logical_cur_asset_commit);
			BigInteger [] logical_pt_total_asset_commit = sid==0?
				logical_pt_cur_asset_commit:
				cm.pointAdd(config, logical_total_asset_commit, cm.xToPoint(config, logical_total_asset_commit)[1], logical_pt_cur_asset_commit[0], logical_pt_cur_asset_commit[1]);
			logical_total_asset_commit = logical_pt_total_asset_commit[0];
			Utils.log(Utils.LOG1, "------ SID: " + sid + " -----");
			Utils.log(Utils.LOG1, "nonce: " + nonce + ", price: " + price + ", shares: " + shares);
			Utils.log(Utils.LOG1, "LOGICAL: cur_asset: " + logical_cur_asset+
				", total asset: " + logical_total_asset + 
				", cur nonce: " + nonce + 
				", total nonce: " + logical_total_nonce+ 
				", cur_asset_commit: " + logical_cur_asset_commit +
				", total_asset: " + logical_total_asset + 
				", total_asset_commit: " + logical_total_asset_commit);
		

			//2.3 update the proof homomorphic side	
			BigInteger prf_shares = pi[2];
			BigInteger [] prf_pt_shares = cm.xToPoint(config,
				prf_shares);
			BigInteger [] prf_pt_cur_asset_commit = cm.pointMul(config, 
				prf_pt_shares[0], prf_pt_shares[1], price);
			prf_cur_asset_commit = prf_pt_cur_asset_commit[0];
			prf_pt_total_asset_commit = sid==0?
				prf_pt_cur_asset_commit:
				cm.pointAdd(config, prf_pt_cur_asset_commit[0], prf_pt_cur_asset_commit[1], prf_pt_total_asset_commit[0], prf_pt_total_asset_commit[1]);
			prf_total_asset_commit = prf_pt_total_asset_commit[0];
			Utils.log(Utils.LOG1, "PROOF side cur_asset_commit: " + 
				prf_cur_asset_commit + ", total_asset_commit: " + 
				prf_total_asset_commit);
	
		}
		BigInteger logical_total_asset_commit2 = cm.pedersen(config, logical_total_nonce, logical_total_asset);
		Utils.log(Utils.LOG1, " == Final: logical_total_asset_commit: " + logical_total_asset_commit + ", logical_total_asset_commit2: " + logical_total_asset_commit2 + ", prf_total_asset_commit: " + prf_total_asset_commit);
		if(!logical_total_asset_commit2.equals(prf_total_asset_commit)){
	 		fail("sumCommit=perdersen(sumNonce,sumAsset)");
		}else{
			System.out.println("It's OK. com1: " + logical_total_asset_commit + ", sumCommit from proof: " + prf_total_asset_commit);
		}
	}

	//generate two certs
    private Cert [] genTwoCerts(ZaConfig config, int sid, int [] shares){
		//1. generate the ZaHoldingVerify circ
		BigInteger pk = Utils.itobi(100);
		BigInteger counter = Utils.itobi(200);
		BigInteger nonce = Utils.randbi(250);
		BigInteger SID = Utils.itobi(sid);
		BigInteger ts = Utils.itobi(0);
		BigInteger ts2 = Utils.itobi(1);
		BigInteger q = Utils.itobi(shares[sid]);
		BigInteger q2 = Utils.randbi(20);
		BigInteger order = config.getFieldOrder();
		BigInteger counter2 = counter.add(Utils.itobi(1));
		Cert cert1= new Cert(pk, counter, nonce, SID, q, ts, config);
		Cert cert2= new Cert(pk, counter2, nonce, SID, q2, ts2, config);
		return new Cert [] {cert1, cert2};
	}

	//just print a vec of two numbers
	private void print_vec(String msg, BigInteger [] vec){
		System.out.println(msg + ": " + vec[0] + ", " + vec[1]);
	}
	@Test
	public void testAssertAsset() {
		common cm = new common();
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Pedersen); 
		//1. prepare the price server and constants
		Utils.log(Utils.LOG2, "create price server ...");
		int numStocks = 2;
		PriceServer ps = PriceServer.create(3, numStocks, config, null);
		int [] init_shares = new int [numStocks];
		for(int i=0; i<numStocks; i++) init_shares[i] = i+10;	
		Curve curve = cm.newCurve(config);
		BigInteger sb_order = curve.subgroup_order;
		BigInteger zero = Utils.itobi(0);

		//2. declare the variables for loop
		BigInteger nonce = zero;
		BigInteger prf_cur_asset_commit = zero;
		BigInteger  prf_total_asset_commit = zero;
		BigInteger [] prf_pt_total_asset_commit = null;
		BigInteger logical_cur_asset = zero;
		BigInteger logical_cur_asset_commit = zero;
		BigInteger logical_total_nonce = zero;
		BigInteger logical_total_asset = zero;
		BigInteger logical_total_asset_commit = zero;
		

		//2. loop
		for(int sid=0; sid<numStocks; sid++){
			//2.1 generate the certs and verifier objects 
			MerkleAccumulator dbAcc= MerkleAccumulator.create(10, config, null);
			Cert [] certs = genTwoCerts(config, sid, init_shares);
			Cert cert1 = certs[0]; Cert cert2 = certs[1];
			dbAcc.add_elements(new BigInteger [] {cert1.getRoot()});
			dbAcc.add_elements(new BigInteger [] {cert2.getRoot()});
			ZaHoldingVerifier zaVerify= new ZaHoldingVerifier(config, cert1, cert2, Utils.itobi(0), dbAcc,	null);
			BigInteger [] pi = zaVerify.genRandomInput(0)[0];
			BigInteger [] aw = zaVerify.genRandomInput(0)[1];

			//2.2 update the homomorphic sum on the logical side
			BigInteger shares = cert1.getQ();
			BigInteger price = Utils.itobi(ps.getPrice(0, sid));
			nonce = aw[0];
			BigInteger nonce_price = nonce.multiply(price).mod(sb_order);		
			logical_total_nonce = logical_total_nonce.add(nonce_price).mod(sb_order);
			logical_cur_asset = shares.multiply(price).mod(sb_order);
			logical_total_asset = logical_total_asset.add(logical_cur_asset).mod(sb_order);
			BigInteger [] logical_pt_cur_asset_commit = cm.logical_pedersen(config, nonce_price, shares);
			logical_cur_asset_commit = logical_pt_cur_asset_commit[0];
			BigInteger [] logical_pt_total_asset_commit = sid==0?
				logical_pt_cur_asset_commit:
				cm.pointAdd(config, logical_total_asset_commit, cm.xToPoint(config, logical_total_asset_commit)[1], logical_pt_cur_asset_commit[0], logical_pt_cur_asset_commit[1]);
			logical_total_asset_commit = logical_pt_total_asset_commit[0];
			Utils.log(Utils.LOG1, "------ SID: " + sid + " -----");
			Utils.log(Utils.LOG1, "nonce: " + nonce + ", price: " + price + ", shares: " + shares);
			Utils.log(Utils.LOG1, "LOGICAL: cur_asset: " + logical_cur_asset+
				", total asset: " + logical_total_asset + 
				", cur nonce: " + nonce + 
				", total nonce: " + logical_total_nonce+ 
				", cur_asset_commit: " + logical_cur_asset_commit +
				", total_asset: " + logical_total_asset + 
				", total_asset_commit: " + logical_total_asset_commit);
		

			//2.3 update the proof homomorphic side	
			BigInteger prf_shares = pi[2];
			BigInteger [] prf_pt_shares = cm.xToPoint(config,
				prf_shares);
			BigInteger [] prf_pt_cur_asset_commit = cm.pointMul(config, 
				prf_pt_shares[0], prf_pt_shares[1], price);
			prf_cur_asset_commit = prf_pt_cur_asset_commit[0];
			prf_pt_total_asset_commit = sid==0?
				prf_pt_cur_asset_commit:
				cm.pointAdd(config, prf_pt_cur_asset_commit[0], prf_pt_cur_asset_commit[1], prf_pt_total_asset_commit[0], prf_pt_total_asset_commit[1]);
			prf_total_asset_commit = prf_pt_total_asset_commit[0];
			Utils.log(Utils.LOG1, "PROOF side cur_asset_commit: " + 
				prf_cur_asset_commit + ", total_asset_commit: " + 
				prf_total_asset_commit);
	
		}
		BigInteger logical_total_asset_commit2 = cm.logical_pedersen(config, logical_total_nonce, logical_total_asset)[0];
		Utils.log(Utils.LOG1, " == Final: logical_total_asset_commit: " + logical_total_asset_commit + ", logical_total_asset_commit2: " + logical_total_asset_commit2 + ", prf_total_asset_commit: " + prf_total_asset_commit);
		if(!logical_total_asset_commit2.equals(prf_total_asset_commit)){
	 		fail("sumCommit=perdersen(sumNonce,sumAsset)");
		}else{
			System.out.println("It's OK. com1: " + logical_total_asset_commit + ", sumCommit from proof: " + prf_total_asset_commit);
		}
	}

	@Test
	public void testInvestVerifier() {
		Utils.log(Utils.WARN, "testInvestVerifier");
		ZaConfig config = ZaConfig.defaultConfig();
		Client client = Client.genRandClient(config);
		Cert cert= Cert.genRandCert(10, config);
		ZaCirc zaVerify= new ZaInvestVerifier(config, client, cert, null);
		CircTester.testCirc(zaVerify,0);	
	}

	@Test
	public void testDepositVerifier() {
	  for(int u=0; u<2; u++){
		Utils.log(Utils.WARN, "testDepositVerifier");
		ZaConfig config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Sha); 
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
		BigInteger bres = CircTester.testCirc(zaVerify,u)[0];	
		if(!bres.equals(Utils.itobi(1))){
			Assert.fail("Deposit verification fails returns 0!");
		}
	  }
	}

	@Test
	public void testPow() {
		Utils.log(Utils.WARN, "testPow");
		ZaCirc zaPow= new ZaPow(ZaConfig.defaultConfig(), null, 8);
		CircTester.testCirc(zaPow,0);	
	}
	@Test
	public void testTraceVerifier() {
		Utils.log(Utils.WARN, "testTraceVerifier");
		// the last parameter e.g. 1024 has to be a multiple of 64 
		ZaConfig cfg = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Poseidon); 
		int n = 1024;
		AC ac = AC.rand_clamav_ac(123, n);
		ZaCirc zaTraceVerifier= new ZaTraceVerifier(cfg, null, n, ac.getStateBits());
		CircTester.testCirc(zaTraceVerifier,0);	
	}

	@Test
	public void test_shifted_derivative(){
		Utils.log(Utils.WARN, "test shifted derivative (logical)");
		int np = 4;
		int idx = np-1;  //last one
		int chunk_254bit = 1;
		ZaCirc za= ZaModularVerifier.new_ZaModularVerifier(chunk_254bit, idx, np);
		int [][] testcases = {
			new int [] {1, 2, 3},
			new int [] {1, 2, 3},
		};
		int [] bases = {
			3,
			0
		};
		int [][] expected = {
			new int [] {0, 6, 18},
			new int [] {0, 0, 0}
		};

		//test.
		for(int i=0; i<testcases.length; i++){
			BigInteger base = Utils.itobi(bases[i]);
			BigInteger [] a = Utils.arr_itobi(testcases[i]);
			BigInteger [] exp = Utils.arr_itobi(expected[i]);
			BigInteger [] b = za.logical_get_derivative_shifted(a, base);
			for(int j=0; j<b.length; j++){
				if(!b[j].equals(exp[j])){
					fail("test logical derivative shifted ERR at testcase: i: " 
						+ i + ", j: " + j + 
						", expected: " + exp[j] + ", actual: " + b[j]);
				}
			}	 
		}	

	}


	@Test
	public void testMiMC() {
		Utils.log(Utils.WARN, "testMiMC");
		ZaConfig cfg = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
			ZaConfig.EnumHashAlg.MiMC); 
		//ZaConfig cfg = new ZaConfig(PrimeFieldInfo.Bls381, 
		//	ZaConfig.EnumHashAlg.MiMC); 
		ZaCirc zaMiMC= new ZaMiMC(cfg, null);
		CircTester.testCirc(zaMiMC,0);	
	}
	@Test
	public void testPoseidon() {
		Utils.log(Utils.WARN, "testPoseidon");
		ZaConfig cfg = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
			ZaConfig.EnumHashAlg.Poseidon); 
		//ZaConfig cfg = new ZaConfig(PrimeFieldInfo.Bls381, 
		//	ZaConfig.EnumHashAlg.Poseidon); 
		ZaCirc zaPoseidon= new ZaPoseidon(cfg, null);
		CircTester.testCirc(zaPoseidon,0);	
	}
*/
	public void testModularVerifier_worker(int idx, int np) {
		Utils.warn(" ==== Testing Modular Verifier Component: " + idx  + "===");
		int chunk_254bit = 4;
//		ZaConfig cfg = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
//			ZaConfig.EnumHashAlg.Poseidon); 
		ZaConfig cfg = new ZaConfig(PrimeFieldInfo.Bls381, 
			ZaConfig.EnumHashAlg.Poseidon); 
		ZaCirc za= ZaModularVerifier.new_ZaModularVerifier(cfg, chunk_254bit, idx, np);
		CircTester.testCirc(za,0);	
		Utils.warn("Modular circuit idx: " + idx + " of " + np + " passed.");
	}

	@Test
	public void testModularVerifier(){//SOMEHOW spark contenxt cannot be
		//started multiple times, had to do it this way. Improve later
		int np = 4;
		for(int idx=0; idx<np; idx++){
			testModularVerifier_worker(idx, 4);
		}
	}

}
