/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   BigNum256 Profiler Class.
*	Author: Dr. CorrAuthor
*	Created: 04/18/2022
* *******************************************/
package cs.Employer.profiler;

import cs.Employer.zkregex.Tools;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;
import java.math.BigInteger;
import configuration.Configuration;

/** 
This class provides a number of profiling functions for
measuring the performance of BigNum256
*/
public class BigNum256Profiler{
	public static void profileAdd256(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 Add256");
		for(int i=1; i<arr.length; i++){
			arr[i].add256With(arr[i-1]);
		}
		cfg.endLog("BigNum256 Add256");
	}
	public static void profileAdd8Limbs(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 Add8Limbs");
		for(int i=1; i<arr.length; i++){
			arr[i].addWith_8limbs(arr[i-1]);
		}
		cfg.endLog("BigNum256 Add8Limbs");
	}
	public static void profileSub8Limbs(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 Sub8Limbs");
		for(int i=1; i<arr.length; i++){
			arr[i].subWith_8limbs(arr[i-1]);
		}
		cfg.endLog("BigNum256 Sub8Limbs");
	}
	public static void profileAbsSub8Limbs(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 AbsSub8Limbs");
		for(int i=1; i<arr.length; i++){
			arr[i].abssubWith_8limbs(arr[i-1]);
		}
		cfg.endLog("BigNum256 AbsSub8Limbs");
	}
	public static void profileNeg8Limbs(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 Neg8Limbs");
		for(int i=1; i<arr.length; i++){
			arr[i].neg_8limbs();
		}
		cfg.endLog("BigNum256 Neg8Limbs");
	}
	public static void profileBigIntAdd(Configuration cfg, BigInteger [] arr){
		cfg.beginLog("BigInteger Add256");
		for(int i=1; i<arr.length; i++){
			arr[i] = arr[i].add(arr[i]);
		}
		cfg.endLog("BigInteger Add256");
	}
	public static void profileBigIntMul(Configuration cfg, BigInteger [] arr){
		cfg.beginLog("BigInteger Mul256");
		for(int i=1; i<arr.length; i++){
			arr[i] = arr[i].multiply(arr[i]);
		}
		cfg.endLog("BigInteger Mul256");
	}
	public static void profileBigIntMulMod(Configuration cfg, BigInteger [] arr){
		cfg.beginLog("BigInteger MulMod256");
		for(int i=0; i<arr.length-2; i++){
			arr[i] = arr[i].multiply(arr[i+1]).mod(arr[i+2]);
		}
		cfg.endLog("BigInteger MulMod256");
	}
	public static void profileBigIntMulModFixed(Configuration cfg, BigInteger [] arr){
		BigInteger r = new BigInteger("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16);
		cfg.beginLog("BigInteger MulMod256Fixed");
		for(int i=0; i<arr.length-2; i++){
			arr[i] = (arr[i].multiply(arr[i+1]));
			arr[i] = arr[i].mod(r);
		}
		cfg.endLog("BigInteger MulMod256Fixed");
	}
	public static void profileMul256(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum256 Mul256");
		for(int i=0; i<arr.length-1; i++){
			arr[i].mul256With(arr[i+1]);
		}
		cfg.endLog("BigNum256 Mul256");
	}
	public static void profileMul512(Configuration cfg, BigNum256 [] arr){
		cfg.beginLog("BigNum512 Mul512");
		for(int i=0; i<arr.length-1; i++){
			arr[i].mul512With(arr[i+1]);
		}
		cfg.endLog("BigNum512 Mul512");
	}
	public static void profileMonPro(Configuration cfg, BigNum256 [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();	
		cfg.beginLog("BigNum MonPro");
		for(int i=0; i<arr.length-1; i++){
			fp.MonPro(arr[i], arr[i+1], arr[i+1]);
		}
		cfg.endLog("BigNum MonPro");
	}
	public static void profileMulLong(Configuration cfg, long [] arr){
		cfg.beginLog("long Mul");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] * arr[i+1];
		}
		cfg.endLog("long Mul");
	}
	public static void profileAddLong(Configuration cfg, long [] arr){
		cfg.beginLog("long Add");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] + arr[i+1];
		}
		cfg.endLog("long Add");
	}
	public static void profileShiftLong(Configuration cfg, long [] arr){
		cfg.beginLog("long Shift");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] >>> 32;
		}
		cfg.endLog("long Shift");
	}
	public static void profileAndLong(Configuration cfg, long [] arr){
		cfg.beginLog("long And");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] & 0x0FFFFFFFF;
		}
		cfg.endLog("long And");
	}
	public static void profileMulInt(Configuration cfg, int [] arr){
		cfg.beginLog("int Mul");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] * arr[i+1];
		}
		cfg.endLog("int Mul");
	}
	public static void profileAddInt(Configuration cfg, int [] arr){
		cfg.beginLog("int Add");
		for(int i=0; i<arr.length-1; i++){
			arr[i] = arr[i] + arr[i+1];
		}
		cfg.endLog("int Add");
	}
	public static void profileMonAdd(Configuration cfg, BigNum256 [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();	
		cfg.beginLog("BigNum MonAdd");
		for(int i=0; i<arr.length-1; i++){
			fp.MonAdd(arr[i], arr[i+1], arr[i]);
		}
		cfg.endLog("BigNum MonAdd");
	}
	public static void profileMonSub(Configuration cfg, BigNum256 [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();	
		cfg.beginLog("BigNum MonSub");
		for(int i=0; i<arr.length-1; i++){
			fp.MonSub(arr[i], arr[i+1], arr[i]);
		}
		cfg.endLog("BigNum MonSub");
	}
}
