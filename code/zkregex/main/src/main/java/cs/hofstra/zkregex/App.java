/** Efficient Zero Knowledge Project
	Main Controller File
	Author: Dr. CorrAuthor
	Created: 04/09/2022
*/ 
package cs.Employer.zkregex;

import cs.Employer.poly.Polynomial;
import cs.Employer.poly.Fp;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;
import cs.Employer.profiler.BigNum256Profiler;
import cs.Employer.profiler.FFTProfiler;
import cs.Employer.profiler.Bn254aFrProfiler;
import cs.Employer.dizk_driver.*;
import cs.Employer.dizk_driver.standard.*;
import cs.Employer.sigma_driver.*;
import cs.Employer.sigma_driver.standard.*;

import za_interface.za.Utils;
import java.util.ArrayList;
import java.util.Random;
import java.math.BigInteger;
import java.util.Scanner;

import algebra.fields.ComplexField;
import algebra.curves.barreto_naehrig.bn254b.BN254bFields.BN254bFr;
import configuration.Configuration;
import profiler.profiling.FFTProfiling; 
import profiler.profiling.FpArithmeticProfiling; 
import profiler.profiling.FpArithmeticProfiling; 
import profiler.profiling.FixedBaseMSMProfiling; 
import profiler.Profiler;

import algebra.curves.barreto_naehrig.BNFields.*;
import algebra.curves.barreto_naehrig.*;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNG1Parameters;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNG2Parameters;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNGTParameters;
import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;
import algebra.curves.barreto_naehrig.bn254a.BN254aG1;
import algebra.curves.barreto_naehrig.bn254a.BN254aG2;
import algebra.curves.barreto_naehrig.bn254a.BN254aPairing;
import algebra.curves.barreto_naehrig.bn254a.bn254a_parameters.BN254aG1Parameters;
import algebra.curves.barreto_naehrig.bn254a.bn254a_parameters.BN254aG2Parameters;
import cs.Employer.ac.AC;

/**
 * Main class of zkregex.
 * Main Usage:
 * (1) publisher workflow. See scripts/publisher.sh
 * Args: srcDir, destDir, subsetStep, subsetMaxDepth curve_name
 * (see the concept
 * of depth in paper. It's basically the distance from init state.
 * A subset defined by depth are the states and related transitions
 * that are at most the given depth from the init state). SubsetStep
 * means the distance between subsets. For instance, if maxdepth is 200,
 * and subsetStep is 10, then we'll generate subset10, subset20, ... subset200
 * Where srcDir contains the expected virus signature files
 * destDir will be created. 
 * Curve_name: supporting BN254, BLS12_381
 * Output files include
 * 	DFA.dat -- DFA.dat (serialized for reloading), ST.dat (list of all states
 *         and transitions), kzg.dat (bilinear acc), info.txt (information
 *			such as number of final states etc.) 
 *  subset10/ including: kzg.dat (bilinear accumulator), prf.dat (proof that
 *           this is a subset of the entire set).
 *  subset20/ 
 *  ...
 *  subset 200 
 */
public class App 
{
	/** interface for jsnark */
	public static BigInteger [][]gen_circ_input_bn254a(AC ac, ArrayList<AC.Transition> al){
		Configuration cfg = Tools.getCurrentConfig();
		if(cfg==null){
			cfg = Tools.buildLocalConfig1();
		}
		BN254aFr fieldFactory = new BN254aFr(1);
		BN254aG1 g1Factory = BN254aG1Parameters.ONE;
		BN254aG2 g2Factory = BN254aG2Parameters.ONE;
		BN254aPairing pr = new BN254aPairing();
		StandardDizkDriver sdd = new StandardDizkDriver(fieldFactory, g1Factory, g2Factory, pr, cfg);
		BigInteger r1 = Utils.randbi(250);
		BigInteger r2 = Utils.itobi(0);
		BigInteger [][] res = sdd.gen_input_for_circ(ac, al, r1, r2);
		return res;
	}

	/** generate the input for all nodes. MAINLY for testing purpose.
		r - random challenge for evaluating polynomials
		r_inv - inv of r regarding field order (modulus)
		z- blinding factor for polynomial evaluations
		r1, r2 - extra random nonces	 
	 */
	public static BigInteger [][][] gen_all_modular_circ_input_bn254a(String sinp, AC ac, ArrayList<AC.Transition> al, int num_modules, String randcase_id, BigInteger r, BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key){
		Configuration cfg = Tools.getCurrentConfig();
		if(cfg==null){
			cfg = Tools.buildLocalConfig1();
		}
		BN254aFr fieldFactory = new BN254aFr(1);
		BN254aG1 g1Factory = BN254aG1Parameters.ONE;
		BN254aG2 g2Factory = BN254aG2Parameters.ONE;
		BN254aPairing pr = new BN254aPairing();
		StandardDizkDriver sdd = new StandardDizkDriver(fieldFactory, g1Factory, g2Factory, pr, cfg);
		BigInteger [][][] res = sdd.gen_input_for_modular_circ(sinp, ac, al, num_modules, randcase_id, r, r_inv, z, r1, r2, key, "BN254");
		return res;
	}
	/** generate the input for all nodes. MAINLY for testing purpose.
		r - random challenge for evaluating polynomials
		r_inv - inv of r regarding field order (modulus)
		z- blinding factor for polynomial evaluations
		r1, r2 - extra random nonces	 
	 */
	public static BigInteger [][][] gen_all_modular_circ_input_bls381(String sinp, AC ac, ArrayList<AC.Transition> al, int num_modules, String randcase_id, BigInteger r, BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key){
		Configuration cfg = Tools.getCurrentConfig();
		if(cfg==null){
			cfg = Tools.buildLocalConfig1();
		}
		BN254aFr fieldFactory = new BN254aFr(1);
		BN254aG1 g1Factory = BN254aG1Parameters.ONE;
		BN254aG2 g2Factory = BN254aG2Parameters.ONE;
		BN254aPairing pr = new BN254aPairing();
		StandardDizkDriver sdd = new StandardDizkDriver(fieldFactory, g1Factory, g2Factory, pr, cfg);
		BigInteger [][][] res = sdd.gen_input_for_modular_circ(sinp, ac, al, num_modules, randcase_id, r, r_inv, z, r1, r2, key, "Bls381");
		return res;
	}
    public static void main( String[] args ) {
		if(args.length<1){
			Tools.panic("Check scripts/publisher.sh, or prover.sh, or verifier.sh for usage!");
		}
		if(args[0].equals("publisher")){
			Publisher.process(args[1], args[2], args[3], args[4]);
		}else if(args[0].equals("prover")){
			Configuration cfg = Tools.buildLocalConfig1(); //TO IMPROVE
        	BN254aFr fieldFactory = new BN254aFr(1);
        	BN254aG1 g1Factory = BN254aG1Parameters.ONE;
        	BN254aG2 g2Factory = BN254aG2Parameters.ONE;
        	BN254aPairing pr = new BN254aPairing();
			//System.out.println("====\nDEBUG USE 111: pairing is: " + pr + "======\n");
			StandardDizkDriver sdd = new StandardDizkDriver(fieldFactory, g1Factory, g2Factory, pr, cfg);
			StandardSigmaDriver sigd = new StandardSigmaDriver();
			ProverInterface prover = new NonzkDIZKProver(sdd, sigd, cfg);
			prover.process(args[1], args[2], args[3], cfg);
		}else if(args[0].equals("rust_prover")){
			//read scripts/prover.sh
			RustProver prover = new RustProver();
			String acDir = args[1];
			String sBinFile = args[2];
			String sPrfDir = args[3];
			String curve_name = args[4];
			String case_id = args[5];
			int max_nodes = Integer.valueOf(args[6]);	
			prover.process(acDir, sBinFile, sPrfDir, curve_name, case_id, max_nodes);
		}else if(args[0].equals("batch_preprocess")){
			//read scripts/prover.sh
			RustProver prover = new RustProver();
			String curve_name = args[1];
			String job_path = args[2];
			String ac_dir= args[3];
			String work_dir = args[4];
			int np = Integer.valueOf(args[5]);	
			int num_worker = Integer.valueOf(args[6]);	
			int server_id = 0; 
			int n_servers = 1;
			String dfa_file = null;
			if(args.length>8){
				server_id = Integer.valueOf(args[7]);
				n_servers= Integer.valueOf(args[8]);
				dfa_file = args[9];
			}
			if(dfa_file==null){
				dfa_file = ac_dir + "/sigs.dat";
				dfa_file = dfa_file.replace("output", "input");
				System.out.println("!!! USE heurstics: we assume the sigs.dat file of AC-DFA is located at: " + dfa_file + "!!!!\n ==== Make sure sigs.dat is correct by passing to batch_preprocess option for Java app ====\n");
			}
			prover.batch_preprocess(curve_name, job_path, ac_dir,
				work_dir, np, num_worker, server_id, n_servers, dfa_file);
		}else if(args[0].equals("multh_op")){
			RustProver prover = new RustProver();
			String job_file = args[1];
			int num_worker = Integer.valueOf(args[2]);
			String ac_dir = args[3];
			String curve_type = args[4];
			String dfa_sigs_file = args[5];
			int np = Integer.valueOf(args[6]);
			String op = args[7];
			BigInteger key = new BigInteger(args[8]);
			prover.multh_op(curve_type, job_file, ac_dir, num_worker,
				dfa_sigs_file, np, op, key);
		}else if(args[0].equals("debug")){
			debug2();
		}else if(args[0].equals("debugR1cs")){
			debugR1cs();
		}else if(args[0].equals("profiler")){
			profile();
		}else if(args[0].equals("dizk")){
			dizk();
		}else if(args[0].equals("paperdata")){
			PaperData pd = new PaperData();
			pd.collect_all_data();
		}else{
			Tools.panic("Cannot process argument: " + args[0]);
		}
    }

	//-----------------------------------------------------------
	// 				**** ASSISTING FUNCTIONS ****
	//-----------------------------------------------------------
	protected static void dizk(){
		//Configuration cfg = Tools.buildLocalConfig16();
		//Configuration cfg = Tools.buildLocalConfig8();
		//Configuration cfg = Tools.buildLocalConfig4();
		//Configuration cfg = Tools.buildLocalConfig2();
		Configuration cfg = Tools.buildLocalConfig1();

		int size = 1024*1024*10;
		System.out.println("==== PROFILER size: " + size + " ====");
		FpParam256 fp = FpParam256.createBN254aParam();
	}
	protected static void profile(){
		Configuration cfg = Tools.buildLocalConfig8();
		//Configuration cfg = Tools.buildLocalConfig4();
		//Configuration cfg = Tools.buildLocalConfig2();
		//Configuration cfg = Tools.buildLocalConfig1();

		int size = 1024*1024;
		System.out.println("==== PROFILER size: " + size + " ====");
		FpParam256 fp = FpParam256.createBN254aParam();
		Profiler.serialApp("fft", cfg, size);
		Profiler.distributedApp("fft", cfg, size);
	}

	protected static void debug(){ //temp code for developing purpose
		System.out.println("----------- DEBUG -----------------");
		Configuration cfg = Tools.buildLocalConfig1();
/*
		final ComplexField fieldFactory = new ComplexField(1);
        ArrayList<ComplexField> input = new ArrayList<>();
        input.add(new ComplexField(1));
        input.add(new ComplexField(1));
		Polynomial p1 = new Polynomial(input, cfg);
        ArrayList<ComplexField> input2 = new ArrayList<>();
        input2.add(new ComplexField(1));
        input2.add(new ComplexField(2));
		Polynomial p2 = new Polynomial(input2, cfg);
		Polynomial p3 = p1.mul(p2);
		ComplexField res = (ComplexField) p3.eval(new ComplexField(2));
		System.out.println("res: " + res);
*/



		int size = 1024*1024*10;
		System.out.println("Size is " + size);
/*
		final BN254bFr bf = new BN254bFr(2L);
		ArrayList<BN254bFr> a1 = randArr254(size);
		ArrayList<BN254bFr> a2 = randArr254(size);
		Polynomial b1 = new Polynomial(a1, cfg);
		Polynomial b2 = new Polynomial(a2, cfg);
		
		cfg.setContext("Mul-Profile");
        cfg.beginRuntimeMetadata("Size (inputs)", (long) size);
        cfg.beginLog("Mul");
        cfg.beginRuntime("Mul");
		Polynomial b3 = b1.mul(b2);
		b3.getCoefs().count();
        cfg.endRuntime("Mul");
        cfg.endLog("Mul");
        cfg.writeRuntimeLog(cfg.context());

		cfg.beginLog("Add");
		Polynomial b4 = b3.add(b3);
		cfg.endLog("Add");
		cfg.beginLog("Eval");
		//BN254bFr res = (BN254bFr) b4.eval(bf);
		b4.dump_coefs(1);
		cfg.endLog("Eval");
*/
/*
		System.out.println("MUL is done!");
		BN254bFr v2 = (BN254bFr) b2.eval(bf);
		BN254bFr v3 = (BN254bFr) b3.eval(bf);
		BN254bFr v4 = v1.mul(v2);
		System.out.println("v3: " + v3 + ", v4: " + v4);	
*/

/*
		FFTProfiling.serialFFTProfiling(cfg, size);
		FFTProfiling.distributedFFTProfiling(cfg, size);
		FpArithmeticProfiling.BN128FrArithmeticProfiling(cfg, size);
		FpArithmeticProfiling.BN254bFrArithmeticProfiling(cfg, size);
*/
//		FixedBaseMSMProfiling.serialFixedBaseMSMG1Profiling(cfg, size);	
//		FixedBaseMSMProfiling.distributedFixedBaseMSMG1Profiling(cfg, size);	
		//FFTProfiling.serialFFTProfiling(cfg, size);

		BigInteger bi1 = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
		BigInteger bi2 = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
		BigInteger bi3 = new BigInteger("71848242871839275222246405745257275088548364400416034343698204186575808495617");
		cfg.beginLog("BigInteger MulMod");	
		for(int i=0; i<size; i++){
			bi1 = bi1.multiply(bi2).mod(bi3);
		}
		cfg.endLog("BigInteger MulMod");	

		long li1 = 0x123456782234552L;
		long li2 = 0x123456782234553L;
		long li3 = 0x123456782234557L;
		cfg.beginLog("Long MulMod");	
		for(int i=0; i<size; i++){
			li1 = li1*li2%li3;
		}
		cfg.endLog("Long MulMod");	

		int [] arr = new int [size];
		arr[0] = 37;
		arr[1] =372841;
		int mod = 7712323;
		for(int i=2; i<arr.length; i++){
			arr[i] = (arr[i-1]*arr[i-2]);
		}
		cfg.beginLog("int MulMod");	
		for(int i=0; i<size; i++){
			arr[i] = (arr[i/2]*arr[i/2+size/2])%3192031;
		}
		cfg.endLog("int MulMod");	
		System.out.println("arr[1000] is " + arr[1000]);
		System.out.println("n is: " + size);


		//TEST FP
		Fp [] af = new Fp [size];
		for(int i=0; i<af.length; i++) af[i] = Fp.rand();	
		cfg.beginLog("Fp Mul");	
		int sum = 0;
		int [] S = new int [16];
		for(int i=0; i<size; i++){
			Fp.REDC(af[i].T, S);
			sum += S[i%8];
		}
		cfg.endLog("Fp Mul");
		System.out.println("----------- DEBUG DONE v2-----------------");
		System.out.println("ENTER to complete");
		Scanner mo = new Scanner(System.in);
		String enter = mo.nextLine();
		Tools.stopSC(cfg);
	}

	protected static void debug2(){
		Configuration cfg = Tools.buildLocalConfig1();
		int size = 1024*1024*10;
		BigInteger [] arr = Fp.randArrBi(size);
		Fp [] arrfp = new Fp [size];
		for(int i=0; i<size; i++) arrfp[i] = Fp.rand();
		Fp.perfBiAdd(arr, cfg);
		Fp.perfBiMul(arr, cfg);
		Fp.perfBiMod(arr, cfg);
		Fp.perfFpMul1(arrfp, cfg);
		Fp.perfFpMul2(arrfp, cfg);
	}

	/** debug the R1CS parser. TODO: Author1
		(1) in DATA folder created a test folder data_r1cs
		(2) in JSNARK do a VERY SIMPLE circuilt, and copy over the file
		(3) run this function and see the dump matching expectation. 
	*/
	protected static void debugR1cs(){
		//ZkrgxR1CSRelation zr = new ZkrgxR1CSRelation();
		//zr.fromFile("../DATA/debug_r1cs/simple.r1cs");
		//zr.dump(); //inspect if it's dumping the right content
	}


	// ---------------------------------------------
	// region private functions
	// ---------------------------------------------
	private static ArrayList<BN254bFr> randArr254(int size){
		final BN254bFr fieldFactory = new BN254bFr(2L);
        final Random rand = new Random();
        final ArrayList<BN254bFr> arr= new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            arr.add(fieldFactory.random(rand.nextLong(), null));
        }
		return arr;
	}
	
	// ---------------------------------------------
	// endregion private functions
	// ---------------------------------------------
}
