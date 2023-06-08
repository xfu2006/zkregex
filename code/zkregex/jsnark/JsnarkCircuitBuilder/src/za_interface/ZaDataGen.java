/*******************************************************************************
 * Author: CorrAuthor
 * Created: 04/21/2021
 *******************************************************************************/

/*************************************************************
 This is the NEW data generation file that
 generates ALL needed circuits for the journal paper.
* *************************************************************/
package za_interface;

import za_interface.za.Utils;
import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import java.util.ArrayList;
import java.util.Random;
import circuit.structure.CircuitGenerator;
import java.math.BigInteger;
import za_interface.za.circs.basicops.*;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.hash.sha.*;
import za_interface.za.circs.hash.pedersen.*;
import za_interface.za.circs.hash.poseidon.*;
import za_interface.za.circs.hash.mimc.*;
import za_interface.za.circs.commit.*;
import za_interface.za.circs.curve.*;
import za_interface.za.circs.exchange.*;
import za_interface.za.circs.encrypt.block.*;
import za_interface.za.circs.encrypt.pubkey.*;
import za_interface.za.circs.encrypt.hybrid.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.range.*;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.zkreg.*;

public class ZaDataGen{

	// ----------------- Utility Functions ---------------------
	/**
	  Generates the r1cs for the given ZaCirc.
	*/
	public static void genr1cs(ZaCirc circ){
		ZaGenerator zg = circ.getGenerator();
		CircuitGenerator.setActiveCircuitGenerator(zg);
		circ.getConfig().apply_config();
		String dirpath = "circuits";
		Utils.log(Utils.LOG2, "Write Circ: " + circ.getName() + ", Config: " + circ.getConfig().toString());
		PrimeFieldInfo info = circ.getConfig().field_info;
		zg.generateCircuit();
		zg.evalCircuit();
		zg.prepFiles(dirpath, info.name);
		zg.genR1cs(info);
	}

	/** Generate all classes for all configs */
	protected static ArrayList<ZaCirc> long_list(){
		ArrayList<ZaCirc> arr = new ArrayList<ZaCirc>();
		ArrayList<ZaConfig> configs = ZaConfig.enumAllZaConfigs();	
		for(int i=0; i<configs.size(); i++){
			ZaConfig config = configs.get(i);
			Curve curve = Curve.createCurve(config);
			arr.add(new ZaAdd(config, null));
			arr.add(new ZaSplit(config, 256, null));
			if(config.hash_alg == ZaConfig.EnumHashAlg.Sha){
				arr.add(new ZaSha2(config, null));
				arr.add(new ZaSha2Path(config, 16, null)); 
			}
			arr.add(new ZaHashCommit(config, null));
			arr.add(new ZaComputeY(curve, null));
			arr.add(new ZaPointAdd(curve, null));
			arr.add(new ZaPointDouble(curve, null));
			arr.add(new ZaPointMul(curve, null));
			if(config.hash_alg == ZaConfig.EnumHashAlg.Pedersen){
				arr.add(new ZaPedersen(config, null));
			}
			arr.add(new ZaHashCommit(config, null));
			arr.add(new ZaECDH(config, null));
			arr.add(new ZaSpeck128(config, null));
			arr.add(new ZaCBCSpeck(config, 255, null));
			arr.add(new ZaHybridDHSpeck(config, 1001, null));
			MerkleAccumulator ma = new MerkleAccumulator(10, config, null);
			ZaCirc zaVerify= ma.genVerifier();
			arr.add(zaVerify);
			arr.add(new ZaRange(config, 64, null));
			Cert cert = Cert.genRandCert(101, config);
			arr.add(new ZaCertVerifier(config, cert, null));
			PriceServer ps = PriceServer.create(2, 4, config, null);
			ZaPriceVerifier zaPs= new ZaPriceVerifier(config, ps, null);
			arr.add(zaPs);
			Fund fund = Fund.genRandFund(i, 4, 999999999, config);
			ZaCirc zaFund= new ZaFundInitCertVerifier(config, fund, 2, null);
			arr.add(zaFund);
			zaVerify = buildCertReplaceVerifier(config);
			arr.add(zaVerify);
			zaVerify= new ZaBrokerInstructionVerifier(config, null);
			arr.add(zaVerify);
			zaVerify= genOrderVerifier(config, 10, 10, 0);
			arr.add(zaVerify);
			zaVerify= genHoldingVerifier(config, 10);
			arr.add(zaVerify);
			Client client = Client.genRandClient(config);
			arr.add(new ZaInvestVerifier(config, client, cert, null));
			arr.add( genDepositVerifier(config, 10, 10, 0) );
		}
		return arr;
	}

	private static ZaCertReplaceVerifier buildCertReplaceVerifier(ZaConfig config){
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
		BigInteger nonce_hash = Utils.randbi(200);
		Cert cert2= new Cert(pk, counter2, nonce, SID, q2, ts2, config);
		ZaCertReplaceVerifier zaVerify= new ZaCertReplaceVerifier(config, cert1, cert2, dbAcc, nonce_hash, pk, ts2, SID, q_diff, null);
		return zaVerify;
	}

	protected static ZaOrderVerifier genOrderVerifier(ZaConfig config, int levelPriceServer, int levelDbAcc, int decision){
		Utils.log(Utils.LOG1, " -- create price server");
		PriceServer ps = PriceServer.create(4, levelPriceServer, config, null);
		Utils.log(Utils.LOG1, " -- gen fund");
		Fund fund = Fund.genRandFund(2, 3, 900000000, config);
		Utils.log(Utils.LOG1, " -- create acc");
		MerkleAccumulator dbAcc= MerkleAccumulator.create(levelDbAcc, config, null);
		Utils.log(Utils.LOG1, " -- add funds's cert");
		for(int i=0; i<fund.getNumStocks(); i++){
			dbAcc.add_elements(new BigInteger [] {fund.getCert(i).getRoot()});
		}
		//buy/sell 10 shares of shares
	    int ts = 1;
		for(int k=0; k<2; k++){
			boolean bBuy = k%2==0;
			Utils.log(Utils.LOG1, " --  buy op");
			int sid = 1;
			ZaOrderVerifier zaVerify= fund.order(ts, sid, 10, bBuy, ps, dbAcc);
			//BigInteger bres = CircTester.testCirc(zaVerify,u)[0];	
			return zaVerify;
		}
		return null;
	}

	protected static ZaDepositVerifier genDepositVerifier(ZaConfig config, int levelPriceServer, int levelDbAcc, int decision){
		Utils.log(Utils.LOG1, " -- create price server");
		PriceServer ps = PriceServer.create(4, levelPriceServer, config, null);
		Utils.log(Utils.LOG1, " -- gen fund");
		Fund fund = Fund.genRandFund(2, 3, 900000000, config);
		Utils.log(Utils.LOG1, " -- create acc");
		MerkleAccumulator dbAcc= MerkleAccumulator.create(levelDbAcc, config, null);
		Utils.log(Utils.LOG1, " -- add funds's cert");
		for(int i=0; i<fund.getNumStocks(); i++){
			dbAcc.add_elements(new BigInteger [] {fund.getCert(i).getRoot()});
		}
	    int ts = 1;
		BigInteger cash_diff = Utils.itobi(90000);
		ZaDepositVerifier zaVerify= fund.deposit(ts, cash_diff , ps, dbAcc);
		return zaVerify;
	}

	protected static ZaHoldingVerifier genHoldingVerifier(ZaConfig config, int levelDbAcc){
		Utils.log(Utils.WARN, "Gen Holding Verifier Circ ...");
		MerkleAccumulator dbAcc= MerkleAccumulator.create(levelDbAcc, config, null);
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
		BigInteger nonce_hash = Utils.randbi(200);
		Cert cert2= new Cert(pk, counter2, nonce, SID, q2, ts2, config);
		dbAcc.add_elements(new BigInteger [] {cert2.getRoot()});
		ZaHoldingVerifier zaVerify= new ZaHoldingVerifier(config, cert1, cert2, ts, dbAcc,  null);
		return zaVerify;
	}

	/** For debugging purpose, generating a short list */
	protected static ArrayList<ZaCirc> short_list(){
		ArrayList<ZaCirc> arr = new ArrayList<ZaCirc>();
//		ArrayList<ZaConfig> configs = ZaConfig.enumAllZaConfigs();	
		ArrayList<ZaConfig> configs = new ArrayList<ZaConfig>();
		//configs.add(new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Poseidon));
		configs.add(new ZaConfig(PrimeFieldInfo.Bls381, ZaConfig.EnumHashAlg.Poseidon));
//		configs.add(new ZaConfig(PrimeFieldInfo.AURORA));
//		configs.add(new ZaConfig(PrimeFieldInfo.LIBSPARTAN));

		int [] arr_bits = new int [] {16};
		for(int i=0; i<configs.size(); i++){
			ZaConfig config = configs.get(i);
			//arr.add(new ZaSha2(config, null));
			//arr.add(new ZaRSA(config, null));
			//for(int j = 0; j<arr_bits.length; j++){
			//	int bits = arr_bits[j];
			//	arr.add(new ZaPow(config, null, bits));
			//}
//			if(config.hash_alg == ZaConfig.EnumHashAlg.Sha){
//				arr.add(new ZaSha2(config, null));
//			}
//			if(config.hash_alg == ZaConfig.EnumHashAlg.Pedersen){
//				arr.add(new ZaPedersen(config, null));
//			}
//			if(config.hash_alg == ZaConfig.EnumHashAlg.Poseidon){
//				arr.add(new ZaPoseidon(config, null));
//			}
			//arr.add(new ZaSplit(config, 4, null));
			//arr.add(new ZaHashCommit(config, null));
			//arr.add(new ZaAdd(config, null));
//			arr.add(new ZaTraceVerifier(config, null, 1024, 20));
			//arr.add(new ZaMiMC(config, null));
			arr.add(new ZaChainMiMC(config, null, 1));

/*
			//Business Related
			Fund fund = Fund.genRandFund(i, 4, 999999999, config);
			ZaCirc zaFund= new ZaFundInitCertVerifier(config, fund, 2, null);
			arr.add(zaFund);
			Cert cert = Cert.genRandCert(101, config);
			ZaCirc zaVerify= genOrderVerifier(config, 16, 11, 0);
			arr.add(zaVerify);
			zaVerify= genHoldingVerifier(config, 11);
			arr.add(zaVerify);
			Client client = Client.genRandClient(config);
			arr.add(new ZaInvestVerifier(config, client, cert, null));
			arr.add( genDepositVerifier(config, 16, 11, 0) );
*/
		}
		return arr;
	}
	//-----------------------------------------------------
	// ------------ MAIN PROGRAM --------------------------
	//-----------------------------------------------------
	/** use run.sh to run it */	
	public static void main(String [] args){
		Utils.setLogLevel(Utils.LOG2);
		Utils.log(Utils.LOG1, "********************************");	
		Utils.log(Utils.LOG1, "     Generating Circuit Files   ");
		Utils.log(Utils.LOG1, "********************************");	
		//ArrayList<ZaCirc> circs = long_list();
		ArrayList<ZaCirc> circs = short_list();
		for(int i=0; i<circs.size(); i++){
			Utils.log(Utils.LOG1, "===== genr1cs circ name: " + circs.get(i).getName() + " ======"); 
			genr1cs(circs.get(i));
		}
	}


}
