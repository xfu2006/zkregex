/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
* 	Faster Bn254Fr Class using Montgomery Reduction
*	Author: Dr. CorrAuthor
*	Created: 04/26/2022
* *******************************************/
package cs.Employer.poly;

import cs.Employer.zkregex.Tools;
import java.math.BigInteger;
import java.lang.RuntimeException;
import algebra.fields.AbstractFieldElementExpanded;
import common.MathUtils;
import common.Utils;
import java.util.Random;
import java.security.SecureRandom;
import java.io.Serializable;
import java.util.ArrayList;

import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;

/**  This class extendes the DIZK's FieldElementExpanded class
so that we can take advantage of its FFT framework, but at the same
time provide much faster multi-precision arithmetic, using
Montgomery Reduction.
NOTE: at any time the value of a field element is saved as
Montgomery Reduction. Call back_from_mont to retrieve its real value. 
*/


public class Bn254aFr extends MontFieldElement<Bn254aFr> implements
	Serializable{
	// ----------------------------------------------
	// --------------- NEW DATA MEMBERS -------------
	// ----------------------------------------------
	/** at any time, the value is in Montgomery reduced form */
	protected BigNum256 value;
	protected static FpParam256 fp = FpParam256.createBN254aParam();
	protected static boolean bTraceSlow = false;
	protected static final Bn254aFr ZERO = new Bn254aFr( BigNum256.from_bi( new BigInteger("0")));
	protected static final Bn254aFr ONE = new Bn254aFr( BigNum256.from_bi( new BigInteger("1")));
	protected static final Bn254aFr MULGEN = new Bn254aFr( BigNum256.from_bi( new BigInteger("5")));
	protected static final BigInteger ROOT = new BigInteger("19103219067921713944291392827692070036145651957329286315305642004821462161904");

	//-----------------------------------------------------
	//------------ PUBLIC OPERATIONS ----------------------
	//-----------------------------------------------------
	/** Assumption: the input v is a VALID value. That is:
		it is less than the order of Bn254a (check fp.N)
		Note: we do NOT check here for speed 
		NOTE: input is NOW PART of bn254aFr object,
		and it's reduced to Montgomery Representation
	 */
	public Bn254aFr(BigNum256 v){
		this.value = v;
		fp.to_mont(this.value);	 
	}

	/* Make a copy (no to_mont() call. Directly copy value */
	public Bn254aFr(Bn254aFr other){
		this.value = new BigNum256(other.value); 
	}


	/** convert from BN254aFr in DIZK. Note the "N" is different 
		from this class name. */
	public static Bn254aFr from_dizk(BN254aFr other){
		BigInteger number = other.element.toBigInteger(); 
		BigNum256 val = BigNum256.from_bi(number); //valid coz the same Modulus
		Bn254aFr ret = new Bn254aFr(val); //this step has the to_montgomery	
		return ret;
	}

	/** convert to BN254aFr in DIZK: note the "N" */
	public BN254aFr to_dizk(){
		BigInteger real_val = this.toBigInteger();
		BN254aFr ret = new BN254aFr(real_val);
		return ret;
	}

	//------------------------------------------------------
	//------------- INHERITED METHODS ----------------------
	//------------------------------------------------------

	public void copyFrom(Bn254aFr other){
		this.value.copyFrom(other.value);
	}
	/* Return the ORIGINAL value */
	public BigInteger back_from_mont(){ 
		BigNum256 cp = new BigNum256(value);
		fp.backfrom_mont(cp);
		BigInteger res = cp.to_bi();
		return res;
	}

    /* Returns omega s.t. omega^order == one(). 
		Note: it is slow but it is NOT called frequently
		ASSUMPTION: order has to be POWER OF 2!
	*/
    public Bn254aFr rootOfUnity(final long order){
		//this approach is possible when the modulus()-1 is VERY CLOSE
		//to power of 2. 
		//The current implementation is SLOW, but since it's not called often
		//it is ok.
		BigInteger modulus = fp.biN;
		BigInteger exp = modulus.divide(BigInteger.valueOf(order));
		BigInteger val = ROOT.modPow(exp, modulus);
		BigNum256 v = BigNum256.from_bi(val);
		Bn254aFr fr = new Bn254aFr(v);
		return fr;
	}

    /* Returns a generator of the multiplicative subgroup of the field */
    public Bn254aFr multiplicativeGenerator(){
		return new Bn254aFr(MULGEN);
	}

    /* Returns field element as Bn254aFr(value) */
    public Bn254aFr construct(final long value){
		BigInteger bi = BigInteger.valueOf(value);
		BigNum256 bn = BigNum256.from_bi(bi);
		Bn254aFr f1 = new Bn254aFr(bn);

		if(bTraceSlow){
			throw new RuntimeException("ALERT ME on Bn254aFr construct(long). This is SLOW. If ncessary optimize it.");
		}
		return f1;
	}

    /* Returns this as a BigInteger.
		Return the backfrom_mont form because
		the number might be used as an exponent. Needs real value */
    public BigInteger toBigInteger(){
		BigNum256 v = new BigNum256(this.value);
		fp.backfrom_mont(v);
		BigInteger ret = v.to_bi();
		return ret;	
	}

    /* Returns self element */
    public  Bn254aFr self(){
		return this;
	}

    /* Returns this + that */
    public  Bn254aFr add(final Bn254aFr that){
		Bn254aFr cp = new Bn254aFr(this);
		fp.MonAdd(cp.value, that.value, cp.value);
		return cp;
	}

    /* Returns this + that, results -> this */
    public  void addWith(final Bn254aFr that){
		fp.MonAdd(this.value, that.value, this.value);
	}

    /* Returns this + that, results -> dest */
    public  void addTo(final Bn254aFr that, Bn254aFr dest){
		fp.MonAdd(this.value, that.value, dest.value);
	}



    /* Returns this - that */
    public  Bn254aFr sub(final Bn254aFr that){
		Bn254aFr cp = new Bn254aFr(this);
		fp.MonSub(cp.value, that.value, cp.value);
		return cp;
	}

    /* MUTABLE, this - that -> this */
    public  void subWith(final Bn254aFr that){
		fp.MonSub(this.value, that.value, this.value);
	}

    /* MUTABLE, this - that -> this */
    public  void subTo(final Bn254aFr that, Bn254aFr dest){
		fp.MonSub(this.value, that.value, dest.value);
	}


    /* Returns this * that. This and that are IMMUTABLE */
    public  Bn254aFr mul(final Bn254aFr that){
		Bn254aFr cp = new Bn254aFr(this);
		fp.MonPro(cp.value, that.value, cp.value);
		return cp;
	}

    /* Returns this * that. This will be changed */
    public  void mulWith(final Bn254aFr that){
		fp.MonPro(this.value, that.value, this.value);
	}

    /* Returns this * that. This will be changed */
    public  void mulTo(final Bn254aFr that, Bn254aFr dest){
		fp.MonPro(this.value, that.value, dest.value);
	}

    /* Returns the zero element */
    public  Bn254aFr zero(){
		return new Bn254aFr(ZERO);
	}

    public static Bn254aFr create_zero(){
		return new Bn254aFr(ZERO);
	}

    /* Returns if this == zero */
    public  boolean isZero(){
		return this.equals(ZERO);
	}

    /* Returns the one element */
    public  Bn254aFr one(){
		return new Bn254aFr(ONE);
	}

    /* Returns if this == one */
    public  boolean isOne(){
		return this.equals(ONE);
	}

    /* Returns -this */
    public  Bn254aFr negate(){
		Bn254aFr cp = new Bn254aFr(this);
		fp.MonSub(ZERO.value, this.value, cp.value);
		return cp;
	}

    /* Returns -this */
    public  void negateWith(){
		fp.MonSub(ZERO.value, this.value, this.value);
	}

    /* Returns this^2 */
    public  Bn254aFr square(){
		Bn254aFr cp = new Bn254aFr(this);
		fp.MonPro(cp.value, cp.value, cp.value);
		return cp;
	}

    /* Returns this^2 */
    public  void squareWith(){
		fp.MonPro(this.value, this.value, this.value);
	}

    /* Returns this^(-1).
		SLOW version: faster version algorithm here:
		ttp://delta.cs.cinvestav.mx/~francisco/arith/j52moinv.pdf
		Faster version is only needed for Lagrange Interpolation,
		might be needed later.
		If no reverse (i.e. value is 0), return 0
	*/
    public  Bn254aFr inverse(){
		//1. compute (aR)^-1
		if(this.equals(ZERO)){return this.zero();}
		BigInteger ar_1 = this.value.to_bi().modInverse(fp.biN);
		BigNum256 bn_1 = BigNum256.from_bi(ar_1);
		BigNum256 v = new BigNum256();
		//2. MonPro((aR)^-1, R^3 mod N)
		Bn254aFr ret = new Bn254aFr(v);
		fp.MonPro(bn_1, fp.R3, ret.value);
		return ret;	 
	}

    /* Returns this^(-1).
		SLOW version: 
		MUTABLE VERSION. Change itself
		If value is 0, do not exception, just let it be.
	 */
    public void inverseWith(){
		//1. compute (aR)^-1
		if(this.equals(ZERO)){return;}
		BigInteger ar_1 = this.value.to_bi().modInverse(fp.biN);
		BigNum256 bn_1 = BigNum256.from_bi(ar_1);
		BigNum256 v = new BigNum256();
		//2. MonPro((aR)^-1, R^3 mod N)
		fp.MonPro(bn_1, fp.R3, this.value);
	}

    /* Returns the maximum bit length of the values composing the element. */
    public  int bitSize(){
		return 254;
	}

    /**
     * If secureSeed is provided, returns cryptographically secure random field element using byte[].
     * Else if seed is provided, returns pseudorandom field element using long as seed.
     * Else, returns a pseudorandom field element without a seed.
     */
    public  Bn254aFr random(final Long seed, final byte[] secureSeed){
		Random rand = null;
		if(secureSeed!=null){
			rand = new SecureRandom(secureSeed);
		}else if(seed!=null){
			rand = new Random(seed);
		}else{
			rand = new Random();
		}
		BigNum256 val = fp.rand_fp(rand);
		Bn254aFr fr = new Bn254aFr(val);
		return fr;
	}

    /* Returns this == that */
    public  boolean equals(final Bn254aFr other){
		return this.value.equals(other.value);
	}

    /* Returns this as string */
    public  String toString(){
		return this.toBigInteger().toString();
	}

	/* return an random array */
	public static ArrayList<Bn254aFr> randArr(int size){
		BigNum256 [] bi = fp.randArrFp(size);
		//ArrayList<Bn254aFr> al = FFTProfiler.to_bn254afr(arr);
		ArrayList<Bn254aFr> al = new ArrayList<>();
		for(int i=0; i<size; i++){
			al.add(new Bn254aFr(bi[i]));
		}
		return al;
	}
} 
