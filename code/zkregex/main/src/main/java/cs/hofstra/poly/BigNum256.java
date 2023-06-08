/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   BigNum256 Class.
*	Author: Dr. CorrAuthor
*	Created: 04/18/2022
* *******************************************/
package cs.Employer.poly;

import cs.Employer.zkregex.Tools;
import java.math.BigInteger;
import java.util.Random;
import java.io.Serializable;

/** 
This class implements fast 256-bit unsigned number arithmetics.
The standard JavaBigInteger class is too slow. We implement
this class used to provide faster prime field element arithmetics. 
It has actually 512-bit data. 
*/
public class BigNum256 implements Serializable{
	//--------------------------------
	//region DATA Members
	//--------------------------------
	protected int d0; //lowest 32-bit
	protected int d1; 
	protected int d2; 
	protected int d3; 
	protected int d4; 
	protected int d5; 
	protected int d6; 
	protected int d7; 
	protected int d8; 
	protected int d9; 
	protected int d10; 
	protected int d11; 
	protected int d12; 
	protected int d13; 
	protected int d14; 
	protected int d15; 
	protected int d16;//carry stores bit 

	//--------------------------------
	//endregion DATA MEMBERS
	//--------------------------------

	//--------------------------------
	//region PUBLIC Methods
	//--------------------------------
	/** Consturctor: generate a 0 */
	public BigNum256(){
		//generates a ZERO
	}

	/** make a copy of the other */
	public BigNum256(BigNum256 other){
		this.copyFrom(other);
	}

	/** make a random element */
	public static BigNum256 rand(Random rand){
		BigNum256 res = new BigNum256();
		res.d0 = rand.nextInt();
		res.d1 = rand.nextInt();
		res.d2 = rand.nextInt();
		res.d3 = rand.nextInt();
		res.d4 = rand.nextInt();
		res.d5 = rand.nextInt();
		res.d6 = rand.nextInt();
		res.d7 = rand.nextInt();
		return res;
	}

	public static BigNum256 [] randarr(int size){
		Random rand = new Random();
		BigNum256 [] arr = new BigNum256 [size];
		for(int i=0; i<size; i++){
			arr[i] = BigNum256.rand(rand);
		}
		return arr;
	}

	/** return zero */
	public static BigNum256 zero(){
		return new BigNum256();
	}

	/** convert a BigInteger into BigNum.
		Assumption: BigInteger in range [0, 2^256-1]
		Note: we DO NOT performance boundary check!
		Warning: this is just for IO purpose.
		It is SLOW!
	*/
	public static BigNum256 from_bi(BigInteger bi){
		BigInteger [] limbs = new BigInteger [8];	 //256-bits
		BigInteger b32 = new BigInteger("4294967296");
		for(int i=0; i<8; i++){
			limbs[i] = bi.mod(b32);
			bi = bi.shiftRight(32);
		}
		BigNum256 bn = new BigNum256();
		bn.d0 = (int) (limbs[0].longValue()); //chop from 64-bit long to 32
		bn.d1 = (int) (limbs[1].longValue()); 
		bn.d2 = (int) (limbs[2].longValue()); 
		bn.d3 = (int) (limbs[3].longValue()); 
		bn.d4 = (int) (limbs[4].longValue()); 
		bn.d5 = (int) (limbs[5].longValue()); 
		bn.d6 = (int) (limbs[6].longValue()); 
		bn.d7 = (int) (limbs[7].longValue()); 

		return bn;
	}

	/* convert to a BigInteger.
		WARNING: slow!
	 */
	public BigInteger to_bi(){
		int [] v = new int [] {d0, d1, d2, d3, d4, d5, d6, d7};
		BigInteger bi = new BigInteger("0");
		BigInteger b32 = new BigInteger("4294967296");
		for(int i=0; i<8; i++){
			if(i>0){ bi = bi.multiply(b32);}
			long val = v[7-i]  & 0x00000000ffffffffL;
			bi = bi.add(BigInteger.valueOf(val));
		}
		return bi;
	}

	/** get the full 512 bit */
	public BigInteger to_bi512(){
		int [] v = new int [] {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15};
		BigInteger bi = new BigInteger("0");
		BigInteger b32 = new BigInteger("4294967296");
		for(int i=0; i<16; i++){
			if(i>0){ bi = bi.multiply(b32);}
			long val = v[15-i]  & 0x00000000ffffffffL;
			bi = bi.add(BigInteger.valueOf(val));
		}
		return bi;
	}

	/** just dump all contents */
	public void dump(){
		System.out.println("----- dump BigNum256 ----");
		System.out.println("d0: 0x" + Integer.toHexString(d0));
		System.out.println("d1: 0x" + Integer.toHexString(d1));
		System.out.println("d2: 0x" + Integer.toHexString(d2));
		System.out.println("d3: 0x" + Integer.toHexString(d3));
		System.out.println("d4: 0x" + Integer.toHexString(d4));
		System.out.println("d5: 0x" + Integer.toHexString(d5));
		System.out.println("d6: 0x" + Integer.toHexString(d6));
		System.out.println("d7: 0x" + Integer.toHexString(d7));
		System.out.println("d8: 0x" + Integer.toHexString(d8));
		System.out.println("d9: 0x" + Integer.toHexString(d9));
		System.out.println("d10: 0x" + Integer.toHexString(d10));
		System.out.println("d11: 0x" + Integer.toHexString(d11));
		System.out.println("d12: 0x" + Integer.toHexString(d12));
		System.out.println("d13: 0x" + Integer.toHexString(d13));
		System.out.println("d14: 0x" + Integer.toHexString(d14));
		System.out.println("d15: 0x" + Integer.toHexString(d15));
		System.out.println("d16: 0x" + Integer.toHexString(d16));
	}

	/** reset all from other */
	public void copyFrom(BigNum256 other){
		this.d0 = other.d0;
		this.d1 = other.d1;
		this.d2 = other.d2;
		this.d3 = other.d3;
		this.d4 = other.d4;
		this.d5 = other.d5;
		this.d6 = other.d6;
		this.d7 = other.d7;
		this.d8 = other.d8;
		this.d9 = other.d9;
		this.d10 = other.d10;
		this.d11 = other.d11;
		this.d12 = other.d12;
		this.d13 = other.d13;
		this.d14 = other.d14;
		this.d15 = other.d15;
	}

	/** add with the other. The result is STORED BACK into 
		the object. Note: only perform 256-bit add. The
		carry bit is stored in d8. The rest of limbs are NOT cleared
		to zero
	*/
	public void add256With(BigNum256 other){
		long sign = this.addWith_8limbs(other);
		this.d8 = (int) sign;
	}

	public void add512With(BigNum256 other){
		long sign = this.addWith_16limbs(other);
		this.d16 = (int) sign;
	}


	/** ONLY sets the LEAST SIGNIFICANT 256-bits of the product, 
		d8 to d16 are all cleared to 0.*/
	public void mul256With(BigNum256 other){
		long val = 0;
		long c = 0;
		this.d8=0;
		this.d9=0;
		this.d10=0;
		this.d11=0;
		this.d12=0;
		this.d13=0;
		this.d14=0;
		this.d15=0;
		this.d16=0;
		//UNROLL of gen_half_mul_limbs(8) of karatsuba_v2.py
long x0 = this.d0 & 0x0FFFFFFFFL;
long x1 = this.d1 & 0x0FFFFFFFFL;
long x2 = this.d2 & 0x0FFFFFFFFL;
long x3 = this.d3 & 0x0FFFFFFFFL;
long x4 = this.d4 & 0x0FFFFFFFFL;
long x5 = this.d5 & 0x0FFFFFFFFL;
long x6 = this.d6 & 0x0FFFFFFFFL;
long x7 = this.d7 & 0x0FFFFFFFFL;
long x8 = this.d8 & 0x0FFFFFFFFL;
long x9 = this.d9 & 0x0FFFFFFFFL;
long x10 = this.d10 & 0x0FFFFFFFFL;
long x11 = this.d11 & 0x0FFFFFFFFL;
long x12 = this.d12 & 0x0FFFFFFFFL;
long x13 = this.d13 & 0x0FFFFFFFFL;
long x14 = this.d14 & 0x0FFFFFFFFL;
long x15 = this.d15 & 0x0FFFFFFFFL;
long y0 = other.d0 & 0x0FFFFFFFFL;
long y1 = other.d1 & 0x0FFFFFFFFL;
long y2 = other.d2 & 0x0FFFFFFFFL;
long y3 = other.d3 & 0x0FFFFFFFFL;
long y4 = other.d4 & 0x0FFFFFFFFL;
long y5 = other.d5 & 0x0FFFFFFFFL;
long y6 = other.d6 & 0x0FFFFFFFFL;
long y7 = other.d7 & 0x0FFFFFFFFL;
long z0 = 0;
long z1 = 0;
long z2 = 0;
long z3 = 0;
long z4 = 0;
long z5 = 0;
long z6 = 0;
long z7 = 0;
// HALF MUL: 
// ['z0', 'z1', 'z2', 'z3', 'z4', 'z5', 'z6', 'z7'] = ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7'] * ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7']
z0 = 0;
z1 = 0;
z2 = 0;
z3 = 0;
z4 = 0;
z5 = 0;
z6 = 0;
z7 = 0;
c = 0;
val = z0 + (x0 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z0 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z1 + (x1 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z1 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z2 + (x2 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z3 + (x3 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z4 + (x4 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z5 + (x5 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x6 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x7 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z1 + (x0 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z1 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z2 + (x1 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z3 + (x2 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z4 + (x3 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z5 + (x4 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x5 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x6 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z2 + (x0 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z3 + (x1 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z4 + (x2 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z5 + (x3 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x4 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x5 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z3 + (x0 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
z3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z4 + (x1 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
z4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z5 + (x2 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x3 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x4 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z4 + (x0 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
z4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z5 + (x1 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x2 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x3 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z5 + (x0 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
z5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z6 + (x1 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x2 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z6 + (x0 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
z6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = z7 + (x1 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
c = 0;
val = z7 + (x0 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
z7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
this.d0 =  (int)  z0;
this.d1 =  (int)  z1;
this.d2 =  (int)  z2;
this.d3 =  (int)  z3;
this.d4 =  (int)  z4;
this.d5 =  (int)  z5;
this.d6 =  (int)  z6;
this.d7 =  (int)  z7;
		//END OF UNROLL of gen_half_mul_limbs(8) of karatsuba_v2.py
	
	}

	/** ONLY sets the 512-bit of the product
		d16 is cleared to 0.
		Operands are regarded as UNSIGNED 32-bit int
	*/
	public void mul512With(BigNum256 other){
		long val = 0;
		long c = 0;
		//UNROLL of gen_mul_limbs(8) in karatsuba_v2.py
long x0 = this.d0 & 0x0FFFFFFFFL;
long x1 = this.d1 & 0x0FFFFFFFFL;
long x2 = this.d2 & 0x0FFFFFFFFL;
long x3 = this.d3 & 0x0FFFFFFFFL;
long x4 = this.d4 & 0x0FFFFFFFFL;
long x5 = this.d5 & 0x0FFFFFFFFL;
long x6 = this.d6 & 0x0FFFFFFFFL;
long x7 = this.d7 & 0x0FFFFFFFFL;
long x8 = this.d8 & 0x0FFFFFFFFL;
long x9 = this.d9 & 0x0FFFFFFFFL;
long x10 = this.d10 & 0x0FFFFFFFFL;
long x11 = this.d11 & 0x0FFFFFFFFL;
long x12 = this.d12 & 0x0FFFFFFFFL;
long x13 = this.d13 & 0x0FFFFFFFFL;
long x14 = this.d14 & 0x0FFFFFFFFL;
long x15 = this.d15 & 0x0FFFFFFFFL;
long y0 = other.d0 & 0x0FFFFFFFFL;
long y1 = other.d1 & 0x0FFFFFFFFL;
long y2 = other.d2 & 0x0FFFFFFFFL;
long y3 = other.d3 & 0x0FFFFFFFFL;
long y4 = other.d4 & 0x0FFFFFFFFL;
long y5 = other.d5 & 0x0FFFFFFFFL;
long y6 = other.d6 & 0x0FFFFFFFFL;
long y7 = other.d7 & 0x0FFFFFFFFL;
long s0 = 0;
long s1 = 0;
long s2 = 0;
long s3 = 0;
long s4 = 0;
long s5 = 0;
long s6 = 0;
long s7 = 0;
long s8 = 0;
long s9 = 0;
long s10 = 0;
long s11 = 0;
long s12 = 0;
long s13 = 0;
long s14 = 0;
long s15 = 0;
// standard MUL: 
// ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15'] = ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7'] * ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6', 'y7'] + 0
s0 = 0;
s1 = 0;
s2 = 0;
s3 = 0;
s4 = 0;
s5 = 0;
s6 = 0;
s7 = 0;
s8 = 0;
s9 = 0;
s10 = 0;
s11 = 0;
s12 = 0;
s13 = 0;
s14 = 0;
s15 = 0;
c = 0;
val = s0 + (x0 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s0 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s1 + (x1 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s1 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s2 + (x2 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s3 + (x3 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s4 + (x4 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s5 + (x5 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x6 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x7 &0x0FFFFFFFFL) *  ((y0&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s1 + (x0 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s1 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s2 + (x1 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s3 + (x2 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s4 + (x3 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s5 + (x4 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x5 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x6 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x7 &0x0FFFFFFFFL) *  ((y1&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s2 + (x0 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s2 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s3 + (x1 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s4 + (x2 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s5 + (x3 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x4 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x5 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x6 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x7 &0x0FFFFFFFFL) *  ((y2&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s3 + (x0 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s3 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s4 + (x1 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s5 + (x2 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x3 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x4 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x5 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x6 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + (x7 &0x0FFFFFFFFL) *  ((y3&0x0FFFFFFFFL) ) +  c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s4 + (x0 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s4 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s5 + (x1 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x2 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x3 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x4 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x5 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + (x6 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + (x7 &0x0FFFFFFFFL) *  ((y4&0x0FFFFFFFFL) ) +  c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s5 + (x0 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s5 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s6 + (x1 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x2 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x3 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x4 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + (x5 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + (x6 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + (x7 &0x0FFFFFFFFL) *  ((y5&0x0FFFFFFFFL) ) +  c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s6 + (x0 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s6 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s7 + (x1 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x2 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x3 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + (x4 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + (x5 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + (x6 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + (x7 &0x0FFFFFFFFL) *  ((y6&0x0FFFFFFFFL) ) +  c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
c = 0;
val = s7 + (x0 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s7 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s8 + (x1 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s8 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s9 + (x2 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s9 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s10 + (x3 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s10 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s11 + (x4 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s11 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s12 + (x5 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s12 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s13 + (x6 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s13 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s14 + (x7 &0x0FFFFFFFFL) *  ((y7&0x0FFFFFFFFL) ) +  c;
s14 =  val & 0x0FFFFFFFFL;
c = val >>> 32; 
val = s15 + c;
s15 =  val & 0x0FFFFFFFFL;
x0 = (int) s0;
x1 = (int) s1;
x2 = (int) s2;
x3 = (int) s3;
x4 = (int) s4;
x5 = (int) s5;
x6 = (int) s6;
x7 = (int) s7;
x8 = (int) s8;
x9 = (int) s9;
x10 = (int) s10;
x11 = (int) s11;
x12 = (int) s12;
x13 = (int) s13;
x14 = (int) s14;
x15 = (int) s15;
this.d0 =  (int)  x0;
this.d1 =  (int)  x1;
this.d2 =  (int)  x2;
this.d3 =  (int)  x3;
this.d4 =  (int)  x4;
this.d5 =  (int)  x5;
this.d6 =  (int)  x6;
this.d7 =  (int)  x7;
this.d8 =  (int)  x8;
this.d9 =  (int)  x9;
this.d10 =  (int)  x10;
this.d11 =  (int)  x11;
this.d12 =  (int)  x12;
this.d13 =  (int)  x13;
this.d14 =  (int)  x14;
this.d15 =  (int)  x15;
		//END OF UNROLL of gen_mul_limbs(8) in karatsuba_v2.py
	}

	@Override
	public boolean equals(Object other){
		BigNum256 b = (BigNum256) other;
		return 
			this.d0==b.d0 &&
			this.d1==b.d1 &&
			this.d2==b.d2 &&
			this.d3==b.d3 &&
			this.d4==b.d4 &&
			this.d5==b.d5 &&
			this.d6==b.d6 &&
			this.d7==b.d7 &&
			this.d8==b.d8 &&
			this.d9==b.d9 &&
			this.d10==b.d10 &&
			this.d11==b.d11 &&
			this.d12==b.d12 &&
			this.d13==b.d13 &&
			this.d14==b.d14 &&
			this.d15==b.d15 &&
			this.d16==b.d16;
	}

	// -------------------------------------------------------------------
	// ------------- The Following are Related to Karatsuba Multiplication	
	// -------------------------------------------------------------------

	/** Add 256-bit and return a sign of either 1 or 0. 
		Code generated by gen_add_8limbs in karatsuba.py  in 
		scripts/unroll_scripts
	*/
	public long addWith_8limbs(BigNum256 b){
		//UNROLL gen_add_8limbs
long val = 0;
long carry = 0;
val = (this.d0&0x0FFFFFFFFL) + (b.d0&0x0FFFFFFFFL) + carry;
this.d0 = (int) val;
carry = (val >>>32); 
val = (this.d1&0x0FFFFFFFFL) + (b.d1&0x0FFFFFFFFL) + carry;
this.d1 = (int) val;
carry = (val >>>32); 
val = (this.d2&0x0FFFFFFFFL) + (b.d2&0x0FFFFFFFFL) + carry;
this.d2 = (int) val;
carry = (val >>>32); 
val = (this.d3&0x0FFFFFFFFL) + (b.d3&0x0FFFFFFFFL) + carry;
this.d3 = (int) val;
carry = (val >>>32); 
val = (this.d4&0x0FFFFFFFFL) + (b.d4&0x0FFFFFFFFL) + carry;
this.d4 = (int) val;
carry = (val >>>32); 
val = (this.d5&0x0FFFFFFFFL) + (b.d5&0x0FFFFFFFFL) + carry;
this.d5 = (int) val;
carry = (val >>>32); 
val = (this.d6&0x0FFFFFFFFL) + (b.d6&0x0FFFFFFFFL) + carry;
this.d6 = (int) val;
carry = (val >>>32); 
val = (this.d7&0x0FFFFFFFFL) + (b.d7&0x0FFFFFFFFL) + carry;
this.d7 = (int) val;
carry = (val >>>32); 
		//END OF UNROLL gen_add_8limbs
		return carry;
	}

	/** Add 512-bit and return a sign of either 1 or 0. 
		Code generated by gen_add_8limbs in karatsuba.py  in 
		scripts/unroll_scripts
	*/
	public long addWith_16limbs(BigNum256 b){
		return 0;
	}

	/* including d16, do division by 2^256 */
	public void shift256(){
		//DO SOMETHING
	}
	/** 256-bit negation of itself.
		check gen_neg_limbs(n) of Karatsuba.py
	*/
	public void neg_8limbs(){
		//UNROLL neg_8limbs 
long val = 0;
long c = 1;
val =  ((~this.d0) & 0x0FFFFFFFFL) +  c;
this.d0 = (int) val;
c = (val >>>32); 
val =  ((~this.d1) & 0x0FFFFFFFFL) +  c;
this.d1 = (int) val;
c = (val >>>32); 
val =  ((~this.d2) & 0x0FFFFFFFFL) +  c;
this.d2 = (int) val;
c = (val >>>32); 
val =  ((~this.d3) & 0x0FFFFFFFFL) +  c;
this.d3 = (int) val;
c = (val >>>32); 
val =  ((~this.d4) & 0x0FFFFFFFFL) +  c;
this.d4 = (int) val;
c = (val >>>32); 
val =  ((~this.d5) & 0x0FFFFFFFFL) +  c;
this.d5 = (int) val;
c = (val >>>32); 
val =  ((~this.d6) & 0x0FFFFFFFFL) +  c;
this.d6 = (int) val;
c = (val >>>32); 
val =  ((~this.d7) & 0x0FFFFFFFFL) +  c;
this.d7 = (int) val;
c = (val >>>32); 
		//END OF UNROLL neg_8limbs 
	}

	/** perform this-other and results stored in this.
		Both operands are regarded as 256-bit UNSIGNED Number
		return the SIGN (not overflow). 1 means neg, 0 otherwise.
	*/
	public long subWith_8limbs(BigNum256 other){
		long sign = 0;
		//UNROLL gen_sub_limbs in karatsuba.py
long val = 0;
long c = 0;
c = (this.d0 &0x0FFFFFFFFL) -  ((other.d0&0x0FFFFFFFFL) ) +  c;
this.d0 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d1 &0x0FFFFFFFFL) -  ((other.d1&0x0FFFFFFFFL) ) +  c;
this.d1 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d2 &0x0FFFFFFFFL) -  ((other.d2&0x0FFFFFFFFL) ) +  c;
this.d2 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d3 &0x0FFFFFFFFL) -  ((other.d3&0x0FFFFFFFFL) ) +  c;
this.d3 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d4 &0x0FFFFFFFFL) -  ((other.d4&0x0FFFFFFFFL) ) +  c;
this.d4 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d5 &0x0FFFFFFFFL) -  ((other.d5&0x0FFFFFFFFL) ) +  c;
this.d5 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d6 &0x0FFFFFFFFL) -  ((other.d6&0x0FFFFFFFFL) ) +  c;
this.d6 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d7 &0x0FFFFFFFFL) -  ((other.d7&0x0FFFFFFFFL) ) +  c;
this.d7 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
c = (this.d8 &0x0FFFFFFFFL) -  ((other.d8&0x0FFFFFFFFL) ) +  c;
this.d8 = (int) c;
c = (c &0x8000000000000000L) >> 63; 
sign = this.d8>>>63;
		//END of UNROLL gen_sub_limbs
		return sign;
	}

	/** perform this-other and results stored in this. Both
		are regarded as 256-bit UNSIGNED NUMBER.
		return the SIGN (not overflow). 1 means neg, 0 otherwise.
		The RESULT stored will be the ABSOLUTE VALUE of: this - other.
	*/
	public long abssubWith_8limbs(BigNum256 other){
		long sign = 0;
		//UNROLL gen_abssub_8limbs in karatsuba.py
long val = 0;
long c = 0;
val = (this.d0 &0x0FFFFFFFFL) -  ((other.d0&0x0FFFFFFFFL) ) +  c;
this.d0 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d1 &0x0FFFFFFFFL) -  ((other.d1&0x0FFFFFFFFL) ) +  c;
this.d1 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d2 &0x0FFFFFFFFL) -  ((other.d2&0x0FFFFFFFFL) ) +  c;
this.d2 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d3 &0x0FFFFFFFFL) -  ((other.d3&0x0FFFFFFFFL) ) +  c;
this.d3 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d4 &0x0FFFFFFFFL) -  ((other.d4&0x0FFFFFFFFL) ) +  c;
this.d4 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d5 &0x0FFFFFFFFL) -  ((other.d5&0x0FFFFFFFFL) ) +  c;
this.d5 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d6 &0x0FFFFFFFFL) -  ((other.d6&0x0FFFFFFFFL) ) +  c;
this.d6 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d7 &0x0FFFFFFFFL) -  ((other.d7&0x0FFFFFFFFL) ) +  c;
this.d7 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
val = (this.d8 &0x0FFFFFFFFL) -  ((other.d8&0x0FFFFFFFFL) ) +  c;
this.d8 = (int) val;
c = (val &0x8000000000000000L) >> 63; 
sign = this.d8>>>63;
if(sign!=0){
val = 0;
c = 1;
val =  ((~this.d0) & 0x0FFFFFFFFL) +  c;
this.d0 = (int) val;
c = (val >>>32); 
val =  ((~this.d1) & 0x0FFFFFFFFL) +  c;
this.d1 = (int) val;
c = (val >>>32); 
val =  ((~this.d2) & 0x0FFFFFFFFL) +  c;
this.d2 = (int) val;
c = (val >>>32); 
val =  ((~this.d3) & 0x0FFFFFFFFL) +  c;
this.d3 = (int) val;
c = (val >>>32); 
val =  ((~this.d4) & 0x0FFFFFFFFL) +  c;
this.d4 = (int) val;
c = (val >>>32); 
val =  ((~this.d5) & 0x0FFFFFFFFL) +  c;
this.d5 = (int) val;
c = (val >>>32); 
val =  ((~this.d6) & 0x0FFFFFFFFL) +  c;
this.d6 = (int) val;
c = (val >>>32); 
val =  ((~this.d7) & 0x0FFFFFFFFL) +  c;
this.d7 = (int) val;
c = (val >>>32); 
val =  ((~this.d8) & 0x0FFFFFFFFL) +  c;
this.d8 = (int) val;
c = (val >>>32); 
}
		//END OF UNROLL gen_abssub_8limbs in karatsuba.py
		return sign;
	}


	/** Karatsuba 8-limbs multiplication. 256 bit UNSIGNED Mul,  512bit prod 
		This function is GIVEN UP.
		2 -lims 166ms (vs 90ms of schoolbook)
		4- limbs 474ms (vs 166 ms of schoolbook)
		8 limbs - 58 seconds!!!! (vs 440ms of school book).
		Guess: JIT fails to work given too many local vars.
		Code is generated by karatsuba_v2.py gen_kara_mul_limbs(n)
	*/
	public void kara_mulWith_8limbs(BigNum256 other){
		long sign = 0;
		long val = 0;
		long c = 0;
		//UNROLL see gen_kara_mul in karatsuba.py
		//!!! Abandoned TOO SLOW !!!
		//END of UNROLL see gen_kara_mul in karatsuba.py
	}

		
	//--------------------------------
	//endregion PUBLIC Methods
	//--------------------------------

	//--------------------------------
	//region protected Methods
	//--------------------------------
	//--------------------------------
	//endregion protected Methods
	//--------------------------------

}
