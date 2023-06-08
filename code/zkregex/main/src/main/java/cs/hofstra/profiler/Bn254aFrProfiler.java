/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Fr256aFr Profiler Class.
*	Author: Dr. CorrAuthor
*	Created: 04/27/2022
* *******************************************/
package cs.Employer.profiler;

import cs.Employer.zkregex.Tools;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;
import cs.Employer.poly.Bn254aFr;
import java.math.BigInteger;
import configuration.Configuration;
import java.lang.RuntimeException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;

/** 
This class provides a number of profiling functions for
measuring the performance of Fr254aFr 
*/
public class Bn254aFrProfiler{
	// op 0: mul, op 1: add, op 2: sub, op 3: square, op 4: inverse
	// op 5: negate
	public static void profileOp(Configuration cfg, BigNum256 [] arrI, int op){

		Bn254aFr [] arr = new Bn254aFr[arrI.length];
		for(int i=0; i<arr.length; i++){
			arr[i] = new Bn254aFr(arrI[i]);
		}
		String [] ops = {"Mul", "Add", "Sub", "Square", "Inverse", "Neg"};
		String sop = ops[op];

		cfg.beginLog("Bn254aFr " + sop);
		if(op==0){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].mul(arr[i+1]);
			}
		}else if(op==1){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].add(arr[i+1]);
			}
		}else if(op==2){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].sub(arr[i+1]);
			}
		}else if(op==3){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].square();
			}
		}else if(op==4){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].inverse();
			}
		}else if(op==5){
			for(int i=0; i<arr.length-1; i++){
				arr[i] = arr[i].negate();
			}
		}else{
			throw new RuntimeException("op: " + op + " not supported");
		}

		cfg.endLog("Bn254aFr " + sop);

		cfg.beginLog("Bn254aFr " + sop + "With");
		if(op==0){
			for(int i=0; i<arr.length-1; i++){
				arr[i].mulWith(arr[i+1]);
			}
		}else if(op==1){
			for(int i=0; i<arr.length-1; i++){
				arr[i].addWith(arr[i+1]);
			}
		}else if(op==2){
			for(int i=0; i<arr.length-1; i++){
				arr[i].subWith(arr[i+1]);
			}
		}else if(op==3){
			for(int i=0; i<arr.length-1; i++){
				arr[i].squareWith();
			}
		}else if(op==4){
			for(int i=0; i<arr.length-1; i++){
				arr[i].inverseWith();
			}
		}else if(op==5){
			for(int i=0; i<arr.length-1; i++){
				arr[i].negateWith();
			}
		}else{
			throw new RuntimeException("op: " + op + " not supported");
		}
		cfg.endLog("Bn254aFr " + sop + "With");
	}

	public static void profileMul(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 0); //mul
	}
	public static void profileAdd(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 1); //add
	}
	public static void profileSub(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 2); //sub
	}
	public static void profileSquare(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 3); //square
	}
	public static void profileInverse(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 4); //inverse
	}
	public static void profileNegate(Configuration cfg, BigNum256 [] arrI){
		profileOp(cfg, arrI, 5); //negate
	}
	public static void profileRootOfUnity(Configuration cfg, int times){
		Bn254aFr fr = Bn254aFr.create_zero();
		System.out.println("RootOfUnity size: " + times);
		Bn254aFr [] arr = new Bn254aFr [times];
		cfg.beginLog("Bn254aFr RootOfUnity");
		for(int i=0; i<times; i++){
			long order = 1L << ((i%60)+1);
			arr[i] = fr.rootOfUnity(order);	
		}
		cfg.endLog("Bn254aFr RootOfUnity");
	}
	public static void profileList(Configuration cfg, int times){
		Bn254aFr fr = new Bn254aFr(BigNum256.from_bi(new BigInteger("33")));
		Bn254aFr zero = fr.zero();
		System.out.println("List Size : " + times);
		cfg.beginLog("Bn254aFr createArray");
		Bn254aFr [] arr = new Bn254aFr [times];
		cfg.endLog("Bn254aFr createArray");

		cfg.beginLog("Bn254aFr createArrayList");
		ArrayList<Bn254aFr> al = new ArrayList<>(Collections.nCopies(times,zero));
		cfg.endLog("Bn254aFr createArrayList");

		cfg.beginLog("Bn254aFr createArrayList2");
		ArrayList<Bn254aFr> al2 = new ArrayList<>(Arrays.asList(arr));
		cfg.endLog("Bn254aFr createArrayList2");

		cfg.beginLog("Bn254aFr ArrOp");
		for(int i=0; i<times; i++){
			arr[i] = fr;
		}
		cfg.endLog("Bn254aFr ArrOp");
		cfg.beginLog("Bn254aFr ArrListOp");
		for(int i=0; i<times; i++){
			al.set(i, fr);
		}
		cfg.endLog("Bn254aFr ArrListOp");
	}
}
