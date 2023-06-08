/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Prime Field Parameter Class
*	Author: Dr. CorrAuthor
*	Created: 04/20/2022
* *******************************************/
package cs.Employer.poly;

import cs.Employer.zkregex.Tools;
import java.math.BigInteger;
import java.util.Random;
import java.lang.RuntimeException;

/** 
This class is a data class that has the parameters for
a Prime Field of 256-bits. (Suitable for BN254)
As we use Montogmery reduction for 
modular multiplication, the class needs to contain the
corresponding consants. The constant names follow the algorithm
given in:
(1) https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
(2) Kor et al's 96 paper: https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf (Analyzing and Comparing Montgomery Multiplication Algorithms).
We assume that the moduls N is less than 256-bits. [This can be
improved later by replacing BigNum256 with an abstract class as
template. TODO]
*/
public class FpParam256{
	//--------------------------------
	//region DATA Members
	//--------------------------------
	/** the modulus */
	public BigNum256 N; 
	/** the bineary of N, negation of all + 1 */
	public BigNum256 NEG_N;
	/** the same value of N*/
	public BigInteger biN; 
	/** the secondary modulus, required to be 2^r */
	public BigNum256 R;
	/** R * R mod N */
	public BigNum256 R2; 
	/** R*R*R mod N*/
	public BigNum256 R3; 
	/** the same value as R*/
	public BigInteger biR;
	/** log2(R) */
	public int r;
	/** limb size - typically 32 */
	public int b;
	/** N' * N = -1 mod R */
	public BigNum256 INV_N;
	/** the least significant limb of N' */
	public long INV_N0;
	/** R*R' = 1 mod N */
	public BigNum256 INV_R;
	/** same as INV_R */
	public BigInteger biINV_R;
	/** constant 1 */
	public BigNum256 ONE;

	//--------------------------------
	//end region DATA Members
	//--------------------------------
	//--------------------------------
	//region PUBLIC operations 
	//--------------------------------
	/** Create an object of BN254aParam */
	public static FpParam256 createBN254aParam(){
		FpParam256 fp = new FpParam256();
		fp.biN = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
		fp.N = BigNum256.from_bi(fp.biN);
		fp.NEG_N = get_neg_N(fp.N);
		fp.biR = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		fp.R = BigNum256.from_bi(fp.biR);
		fp.R2 = BigNum256.from_bi(new BigInteger("944936681149208446651664254269745548490766851729442924617792859073125903783"));
		fp.R3 = BigNum256.from_bi(new BigInteger("5866548545943845227489894872040244720403868105578784105281690076696998248512"));
		fp.r = 256;
		fp.b = 32;
		fp.biINV_R = new BigInteger("9915499612839321149637521777990102151350674507940716049588462388200839649614");
		fp.INV_R = BigNum256.from_bi(fp.biINV_R);
		fp.INV_N = BigNum256.from_bi(new BigInteger("52454480824480482120356829342366457550537710351690908576382634413609933864959")); 
		fp.INV_N0 = 4026531839L;
		fp.ONE = BigNum256.from_bi(new BigInteger("1"));
		return fp;
	}

	/** Convert a to Montgomery representation, that is:
		aR mod N. 
		Note: a is modified. This is the logical/slow version */
	public void to_mont_logical(BigNum256 a){
		BigInteger bia = a.to_bi();
		BigInteger res = bia.multiply(biR).mod(biN);
		BigNum256 a2= BigNum256.from_bi(res);
		a.copyFrom(a2);
	}

	/* Convert a to AR mod N.
		Idea: call MonPro(a,R^2)
		Requirement: a has to be less than R*N
		We assume a is already in range [0,R] which satisfies it.
	 */
	public void to_mont(BigNum256 a){
		MonPro(a, R2, a);
	}

	/** Convert a FROM Montgomery representation, that is:
		a INV_R mod N.
		Note: a is modified. This is the logical/slow version */
	public void backfrom_mont_logical(BigNum256 a){
		BigInteger bia = a.to_bi();
		BigInteger res = bia.multiply(biINV_R).mod(biN);
		BigNum256 a2= BigNum256.from_bi(res);
		a.copyFrom(a2);
	}

	/** Convert back from Montgomery reduction.
		Assumption: a is in range [0,N]
		Idea:  MonPro(aR, 1) produces aR*R^-1 = a*/
	public void backfrom_mont(BigNum256 a){
		MonPro(a, ONE, a);
	}


	/** generate a random field element.
		Note: could be SLOW */
	public BigNum256 rand_fp(){
		Random rand = new Random();
		BigInteger ele = new BigInteger(512, rand);
		ele = ele.mod(this.biN);
		BigNum256 res = BigNum256.from_bi(ele);
		return res;
	}

	/** generate a random field element. Given the rand object
		Note: could be SLOW */
	public BigNum256 rand_fp(Random rand){
		BigInteger ele = new BigInteger(512, rand);
		ele = ele.mod(this.biN);
		BigNum256 res = BigNum256.from_bi(ele);
		return res;
	}


	/** generate field elements array */
	public BigNum256 [] randArrFp(int size){
		Random rand = new Random();
		BigNum256 [] arr =new BigNum256 [size];
		BigNum256 one = BigNum256.from_bi(new BigInteger("1"));
		for(int i=0; i<size; i++){
			//FASTER
			BigNum256 nele = BigNum256.rand(rand);
			//SLOW ONE - 10 million for 20 seconds
			//BigNum256 nele = BigNum256.from_bi(new BigInteger(256, rand));
			arr[i] = new BigNum256();
			MonPro(nele, one, arr[i]);

/*
			ele = ele.mod(this.biN);
			BigNum256 res = BigNum256.from_bi(ele);
			arr[i] = res;
*/
		}
		return arr;
	}	

	/** logical Montogomery reduction.
		Note: slow!
	*/
	public void logical_REDC(BigNum256 T){
		BigInteger res = T.to_bi512().multiply(this.biINV_R).mod(this.biN);
		BigNum256 t2 = BigNum256.from_bi(res);
		T.copyFrom(t2);
	}

	/* Logical Montogomery Production, assuming a and b are already
		Montgomery representation. Result is written into c */
	public void logical_MonPro(BigNum256 a, BigNum256 b, BigNum256 c){
		c.copyFrom(a);
		c.mul512With(b);
		logical_REDC(c);
	}

	/** perform field operation multiplication and save back to c*/
	public void logical_mul(BigNum256 a, BigNum256 b, BigNum256 c){
		BigInteger bia = a.to_bi(); 
		BigInteger bib = b.to_bi(); 
		BigInteger bic = bia.multiply(bib).mod(this.biN);
		BigNum256 c2 = BigNum256.from_bi(bic);
		c.copyFrom(c2);
	}

	/** We replicate the CIOS algorithm. Assumption: 256-bits
		field elements 
		Ref: https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf.
		Generated by scripts/unroll_scripts/gen_cios.py
	*/
	public void MonPro(BigNum256 a, BigNum256 b, BigNum256 dest){
		//UNROLL 
long c = 0;
long s = 8;
long val = 0;
long m = 0;
long t0 = 0;
long u0 = 0;
long t1 = 0;
long u1 = 0;
long t2 = 0;
long u2 = 0;
long t3 = 0;
long u3 = 0;
long t4 = 0;
long u4 = 0;
long t5 = 0;
long u5 = 0;
long t6 = 0;
long u6 = 0;
long t7 = 0;
long u7 = 0;
long t8 = 0;
long u8 = 0;
long t9 = 0;
long u9 = 0;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d0  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d1  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d2  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d3  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d4  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d5  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d6  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
c = 0;
  val = t0+(a.d0&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t0 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t1+(a.d1&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t1 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+(a.d2&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t2 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+(a.d3&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t3 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+(a.d4&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t4 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+(a.d5&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t5 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+(a.d6&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t6 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+(a.d7&0x0FFFFFFFFL)*(b.d7  & 0x0FFFFFFFFL) + c;
  t7 =  val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t8 = val & 0x0FFFFFFFFL;
t9 = (val >>> 32);
c = 0;
m = (t0 * INV_N0) & 0x0FFFFFFFFL;
val = (t0 + m*(N.d0 & 0x0FFFFFFFFL));
c = (val >>> 32);
  val = t1+ m*(N.d1 & 0x0FFFFFFFFL) +c;
  t0 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t2+ m*(N.d2 & 0x0FFFFFFFFL) +c;
  t1 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t3+ m*(N.d3 & 0x0FFFFFFFFL) +c;
  t2 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t4+ m*(N.d4 & 0x0FFFFFFFFL) +c;
  t3 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t5+ m*(N.d5 & 0x0FFFFFFFFL) +c;
  t4 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t6+ m*(N.d6 & 0x0FFFFFFFFL) +c;
  t5 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
  val = t7+ m*(N.d7 & 0x0FFFFFFFFL) +c;
  t6 = val & 0x0FFFFFFFFL;
  c = (val >>> 32);
val = t8 + c;
t7 = val & 0x0FFFFFFFFL;
c = (val >>> 32);
t8 = t9 + c;
long B = 0;
  val = t0 + (NEG_N.d0 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u0 = val & 0x0FFFFFFFFL;
  val = t1 + (NEG_N.d1 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u1 = val & 0x0FFFFFFFFL;
  val = t2 + (NEG_N.d2 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u2 = val & 0x0FFFFFFFFL;
  val = t3 + (NEG_N.d3 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u3 = val & 0x0FFFFFFFFL;
  val = t4 + (NEG_N.d4 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u4 = val & 0x0FFFFFFFFL;
  val = t5 + (NEG_N.d5 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u5 = val & 0x0FFFFFFFFL;
  val = t6 + (NEG_N.d6 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u6 = val & 0x0FFFFFFFFL;
  val = t7 + (NEG_N.d7 &0x0FFFFFFFFL) + B;
  B = (val >>> 32);
  u7 = val & 0x0FFFFFFFFL;
if(B==0){
  dest.d0 = (int) t0; 
  dest.d1 = (int) t1; 
  dest.d2 = (int) t2; 
  dest.d3 = (int) t3; 
  dest.d4 = (int) t4; 
  dest.d5 = (int) t5; 
  dest.d6 = (int) t6; 
  dest.d7 = (int) t7; 
}else{
  dest.d0 = (int) u0; 
  dest.d1 = (int) u1; 
  dest.d2 = (int) u2; 
  dest.d3 = (int) u3; 
  dest.d4 = (int) u4; 
  dest.d5 = (int) u5; 
  dest.d6 = (int) u6; 
  dest.d7 = (int) u7; 
}
		//END OF UNROLL
	}
	/** Just another version of MonPro, standard version  
	Abaononed. Slower than MonPro.
	*/
	public void MonPro_Abandoned(BigNum256 a, BigNum256 b, BigNum256 dest){
		BigNum256 T = new BigNum256(a);
		T.mul512With(b);
		BigNum256 m = new BigNum256(T);
		m.mul256With(INV_N);
		BigNum256 t = m;
		t.mul512With(N);
		t.add512With(T);
		t.shift256();
		BigNum256 u = new BigNum256(t);
		long sign =  u.subWith_8limbs(t);
		if(sign==0){
			dest.copyFrom(u);
		}else{
			dest.copyFrom(t);
		}		
		throw new RuntimeException("This function is abandoned");
	}

	/** Add in Montgomery form. Assuming a and b is already in
	the right Montgomery reduction, i.e., a and b in [0, N).
	We assume that N is up to 254bits!!! This leads to the trick
	that the sum of two 254-bit numbers can be UP TO 255 bits.
	We simply check bit 255, if it is 255-bit, we minus
	the N on the result.
	Code is generated by gen_add_mon() in karatsuba_v2.py
	*/	
	public void MonAdd(BigNum256 a, BigNum256 b, BigNum256 dest){
		long val = 0;
		long c = 0;
		//UNROLL gen_add_mon() in karatsuba_v2.py
long x0 = a.d0 & 0x0FFFFFFFFL;
long x1 = a.d1 & 0x0FFFFFFFFL;
long x2 = a.d2 & 0x0FFFFFFFFL;
long x3 = a.d3 & 0x0FFFFFFFFL;
long x4 = a.d4 & 0x0FFFFFFFFL;
long x5 = a.d5 & 0x0FFFFFFFFL;
long x6 = a.d6 & 0x0FFFFFFFFL;
long x7 = a.d7 & 0x0FFFFFFFFL;
long y0 = b.d0 & 0x0FFFFFFFFL;
long y1 = b.d1 & 0x0FFFFFFFFL;
long y2 = b.d2 & 0x0FFFFFFFFL;
long y3 = b.d3 & 0x0FFFFFFFFL;
long y4 = b.d4 & 0x0FFFFFFFFL;
long y5 = b.d5 & 0x0FFFFFFFFL;
long y6 = b.d6 & 0x0FFFFFFFFL;
long y7 = b.d7 & 0x0FFFFFFFFL;
long t0 = 0;
long t1 = 0;
long t2 = 0;
long t3 = 0;
long t4 = 0;
long t5 = 0;
long t6 = 0;
long t7 = 0;
// gen_add_to: x:  ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'] , y:  ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7'] , z: ['t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7'] , carry_in:  0
c = 0;
val = x0 + y0 + c;
t0 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x1 + y1 + c;
t1 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x2 + y2 + c;
t2 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x3 + y3 + c;
t3 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x4 + y4 + c;
t4 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x5 + y5 + c;
t5 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x6 + y6 + c;
t6 =  val & 0x0FFFFFFFFL;
c = (val >>>32); 
val = x7 + y7 + c;
t7 =  val & 0x0FFFFFFFFL;
long sign254 = (t7 >>> 30);
if (sign254==1){
long u0 = this.N.d0 & 0x0FFFFFFFFL;
long u1 = this.N.d1 & 0x0FFFFFFFFL;
long u2 = this.N.d2 & 0x0FFFFFFFFL;
long u3 = this.N.d3 & 0x0FFFFFFFFL;
long u4 = this.N.d4 & 0x0FFFFFFFFL;
long u5 = this.N.d5 & 0x0FFFFFFFFL;
long u6 = this.N.d6 & 0x0FFFFFFFFL;
long u7 = this.N.d7 & 0x0FFFFFFFFL;
// gen_sub_to x: ['t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7'], y: ['u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'u6', 'u7'], z: ['dest.d0', 'dest.d1', 'dest.d2', 'dest.d3', 'dest.d4', 'dest.d5', 'dest.d6', 'dest.d7']
c = 0;
val = t0 - u0 +  c;
dest.d0 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t1 - u1 +  c;
dest.d1 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t2 - u2 +  c;
dest.d2 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t3 - u3 +  c;
dest.d3 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t4 - u4 +  c;
dest.d4 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t5 - u5 +  c;
dest.d5 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t6 - u6 +  c;
dest.d6 =  (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = t7 - u7 +  c;
dest.d7 =  (int) val;
}else{
dest.d0 =  (int)  t0;
dest.d1 =  (int)  t1;
dest.d2 =  (int)  t2;
dest.d3 =  (int)  t3;
dest.d4 =  (int)  t4;
dest.d5 =  (int)  t5;
dest.d6 =  (int)  t6;
dest.d7 =  (int)  t7;
};
		//END of UNROLL gen_add_mon()
	}

	/** Sub in Montgomery form. Assuming a and b is already in
	the right Montgomery reduction, i.e., a and b in [0, N).
	We assume that N is up to 254bits!!! This leads to the trick
	that the difference can be only in range [-2^254<-N, N-1 < 2^254-1]
	We test the sign it, if it's set, plus N 

	NOTE: code generated by gen_sub_mon() in karatsuba_v2.py
	*/	
	public void MonSub(BigNum256 a, BigNum256 b, BigNum256 dest){
		long val = 0;
		long c = 0;
		//UNROLL gen_sub_mon() in karatsuba_v2.py
long x0 = a.d0 & 0x0FFFFFFFFL;
long x1 = a.d1 & 0x0FFFFFFFFL;
long x2 = a.d2 & 0x0FFFFFFFFL;
long x3 = a.d3 & 0x0FFFFFFFFL;
long x4 = a.d4 & 0x0FFFFFFFFL;
long x5 = a.d5 & 0x0FFFFFFFFL;
long x6 = a.d6 & 0x0FFFFFFFFL;
long x7 = a.d7 & 0x0FFFFFFFFL;
long y0 = b.d0 & 0x0FFFFFFFFL;
long y1 = b.d1 & 0x0FFFFFFFFL;
long y2 = b.d2 & 0x0FFFFFFFFL;
long y3 = b.d3 & 0x0FFFFFFFFL;
long y4 = b.d4 & 0x0FFFFFFFFL;
long y5 = b.d5 & 0x0FFFFFFFFL;
long y6 = b.d6 & 0x0FFFFFFFFL;
long y7 = b.d7 & 0x0FFFFFFFFL;
long t0 = 0;
long t1 = 0;
long t2 = 0;
long t3 = 0;
long t4 = 0;
long t5 = 0;
long t6 = 0;
long t7 = 0;
// gen_sub_to x: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'], y: ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7'], z: ['t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7']
c = 0;
val = x0 - y0 +  c;
t0 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x1 - y1 +  c;
t1 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x2 - y2 +  c;
t2 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x3 - y3 +  c;
t3 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x4 - y4 +  c;
t4 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x5 - y5 +  c;
t5 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x6 - y6 +  c;
t6 = val & 0x0FFFFFFFFL;
c = (val &0x8000000000000000L) >> 63; 
val = x7 - y7 +  c;
t7 = val & 0x0FFFFFFFFL;
long sign255 = (t7 >>> 31);
if (sign255==1){
long u0 = this.N.d0 & 0x0FFFFFFFFL;
long u1 = this.N.d1 & 0x0FFFFFFFFL;
long u2 = this.N.d2 & 0x0FFFFFFFFL;
long u3 = this.N.d3 & 0x0FFFFFFFFL;
long u4 = this.N.d4 & 0x0FFFFFFFFL;
long u5 = this.N.d5 & 0x0FFFFFFFFL;
long u6 = this.N.d6 & 0x0FFFFFFFFL;
long u7 = this.N.d7 & 0x0FFFFFFFFL;
// gen_add_to: x:  ['t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7'] , y:  ['u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'u6', 'u7'] , z: ['dest.d0', 'dest.d1', 'dest.d2', 'dest.d3', 'dest.d4', 'dest.d5', 'dest.d6', 'dest.d7'] , carry_in:  0
c = 0;
val = t0 + u0 + c;
dest.d0 =  (int) val;
c = (val >>>32); 
val = t1 + u1 + c;
dest.d1 =  (int) val;
c = (val >>>32); 
val = t2 + u2 + c;
dest.d2 =  (int) val;
c = (val >>>32); 
val = t3 + u3 + c;
dest.d3 =  (int) val;
c = (val >>>32); 
val = t4 + u4 + c;
dest.d4 =  (int) val;
c = (val >>>32); 
val = t5 + u5 + c;
dest.d5 =  (int) val;
c = (val >>>32); 
val = t6 + u6 + c;
dest.d6 =  (int) val;
c = (val >>>32); 
val = t7 + u7 + c;
dest.d7 =  (int) val;
}else{
dest.d0 =  (int)  t0;
dest.d1 =  (int)  t1;
dest.d2 =  (int)  t2;
dest.d3 =  (int)  t3;
dest.d4 =  (int)  t4;
dest.d5 =  (int)  t5;
dest.d6 =  (int)  t6;
dest.d7 =  (int)  t7;
};
		//END OF UNROLL gen_sub_mon() in karatsuba_v2.py
	}

	//--------------------------------
	//end region PUBLIC operations 
	//--------------------------------
	//--------------------------------
	//region protected OPERATION
	//--------------------------------
	protected static BigNum256 get_neg_N(BigNum256 N){
		BigInteger b256 = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936");
		BigInteger ret = b256.subtract(N.to_bi());
		BigNum256 res = BigNum256.from_bi(ret);
		return res;
	} 	
	//--------------------------------
	//end region protected OPERATION
	//--------------------------------
}
