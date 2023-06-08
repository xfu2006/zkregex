/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Polynomial Class.
*	Author: Dr. CorrAuthor
*	Created: 04/12/2022
* !!!!! THIS CLASS IS Deprecated !!!! NOT USED !!!!
*/
package cs.Employer.poly;

import cs.Employer.ac.AC;
import cs.Employer.zkregex.Tools;
import algebra.fft.DistributedFFT; 
import algebra.fields.AbstractFieldElementExpanded;
import common.MathUtils;
import common.Combiner;
import common.NaiveEvaluation;
import common.Utils;
import configuration.Configuration;
import org.apache.spark.api.java.JavaPairRDD;
import scala.Tuple2;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Random;

import java.math.BigInteger;

/** Experiment class on a Fp256 element
https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
* !!!!! THIS CLASS IS Deprecated !!!! NOT USED !!!!
*/
public class Fp{
	public static int [] N = new int [] { 0x12345f67, 0x112233fa, 0x12345f67, 0x11223344, 0x12345f67, 0x112244fa, 0x12345f67, 0x113344fa} ; //the modulus
	public static int [] R = new int [] {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80000000}; //2^256 
	public static int NP = 0xF2334455;
	public static int r = 8;
	public static int p = 8;
	
	public int [] T = new int [r+p+1];

	public static Fp rand(){
		Fp fp = new Fp();
		Random rand = new Random();
		for(int i=0; i<r+p; i++){
			fp.T[i] = rand.nextInt();
		}
		return fp;
	}
	
	/** produce TR^-1 mod N, assume T is of length r+p, S is the result */
	public static void REDC(int [] T, int [] S){
		T[r+p] = 0;		
		int count = 0;
/*
		for(int i=0; i<r; i++){
			int c = 0;
			int m = T[i] * NP;
			for(int j=0; j<p; j++){
				long x = T[i+j] + m*N[j] + c;
				T[i+j] =  (int) x;
				c = (int) (x>>32);
			}
			for(int j=p; j<=r+p-i; j++){
				long x = T[i+j] + c;
				T[i+j] = (int)x;
				c = (int) (x>>32);
			}
			count += r + p - i;
		}
		for(int i=0; i<p; i++){
			S[i] = T[i+r];
		}
		count += p;
*/
		int T0 = T[0];
		int T1 = T[1];
		int T2 = T[2];
		int T3 = T[3];
		int T4 = T[4];
		int T5 = T[5];
		int T6 = T[6];
		int T7 = T[7];
		int T8 = T[8];
		int T9 = T[9];
		int T10 = T[10];
		int T11 = T[11];
		int T12 = T[12];
		int T13 = T[13];
		int T14 = T[14];
		int T15 = T[15];
		int N0 = N[0];
		int N1 = N[1];
		int N2 = N[2];
		int N3 = N[3];
		int N4 = N[4];
		int N5 = N[5];
		int N6 = N[6];
		int N7 = N[7];
		int c = 0;
		int m = T0*NP;
		long x = T1 + m*N1 + c;
		T2 = (int) x;
		c = (int) (x>>32);
		x = T2 + m*N2 + c;
		T3 = (int) x;
		c = (int) (x>>32);
		x = T3 + m*N3 + c;
		T4 = (int) x;
		c = (int) (x>>32);
		x = T4 + m*N4 + c;
		T5 = (int) x;
		c = (int) (x>>32);
		x = T6 + m*N6 + c;
		T6 = (int) x;
		c = (int) (x>>32);
		x = T7 + m*N7 + c;
		T7 = (int) x;
		c = (int) (x>>32);
		x = T1 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T3 = (int)x; 
		c = (int) (x>>32);
		x = T3 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		T2 = (int) x;
		c = (int) (x>>32);
		x = T2 + m*N2 + c;
		T3 = (int) x;
		c = (int) (x>>32);
		x = T3 + m*N3 + c;
		T4 = (int) x;
		c = (int) (x>>32);
		x = T4 + m*N4 + c;
		T5 = (int) x;
		c = (int) (x>>32);
		x = T6 + m*N6 + c;
		T6 = (int) x;
		c = (int) (x>>32);
		x = T7 + m*N7 + c;
		T7 = (int) x;
		c = (int) (x>>32);
		x = T1 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T3 = (int)x; 
		c = (int) (x>>32);
		x = T3 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		T2 = (int) x;
		c = (int) (x>>32);
		x = T2 + m*N2 + c;
		T3 = (int) x;
		c = (int) (x>>32);
		x = T3 + m*N3 + c;
		T4 = (int) x;
		c = (int) (x>>32);
		x = T4 + m*N4 + c;
		T5 = (int) x;
		c = (int) (x>>32);
		x = T6 + m*N6 + c;
		T6 = (int) x;
		c = (int) (x>>32);
		x = T7 + m*N7 + c;
		T7 = (int) x;
		c = (int) (x>>32);
		x = T1 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T3 = (int)x; 
		c = (int) (x>>32);
		x = T3 + c;
		T1 = (int)x; 
		c = (int) (x>>32);
		x = T2 + c;
		T1 = (int)x; 
		c = (int) (x>>32);

		S[0] = T1;
		S[1] = T2;
		S[2] = T3;
		S[3] = T3;
		S[4] = T4;
		S[5] = T5;
		S[6] = T6;
		S[7] = T7;
	}

	public static BigInteger [] randArrBi(int size){
		BigInteger [] arr = new BigInteger [size];
		Random rand = new Random();
		for(int i=0; i<arr.length; i++){
			arr[i] = new BigInteger(256, rand);
		} 
		return arr;	
	}
	public static void perfBiAdd(BigInteger [] arr, Configuration cfg){
		long start = System.currentTimeMillis();
		for(int i=1; i<arr.length; i++){
			arr[i] = arr[i-1].add(arr[i]);
		}
		long end= System.currentTimeMillis();
		System.out.println("arr[1000] is " + arr[1000]);
		System.out.println("BigInteger add: " + (end-start) + " ms");
	}

	public static void perfBiMul(BigInteger [] arr, Configuration cfg){
		long start = System.currentTimeMillis();
		for(int i=1; i<arr.length; i++){
			arr[i] = arr[i].multiply(arr[0]);
		}
		long end= System.currentTimeMillis();
		System.out.println("arr[1000] is " + arr[1000]);
		System.out.println("BigInteger mul: " + (end-start) + " ms");
	}

	public static void perfBiMod(BigInteger [] arr, Configuration cfg){
		long start = System.currentTimeMillis();
		for(int i=1; i<arr.length; i++){
			arr[i] = arr[i].mod(arr[0]);
		}
		long end= System.currentTimeMillis();
		System.out.println("arr[1000] is " + arr[1000]);
		System.out.println("BigInteger Mod: " + (end-start) + " ms");
	}

	protected int [] TEMP = new int [17];
	protected int [] TEMP2 = new int [17];
	/** simulate the multiplication, only do the RIGHT MOST 8 limbs */
	public void mul1(Fp others){
		int [] a = TEMP;
		for(int i=0; i<a.length; i++){
			a[i] = this.T[i];	
		}
		int [] b = others.T;
		int [] row = TEMP;
		int [] res = this.T;	
		for(int i=0; i<16; i++){
			res[i] = 0;
		}
		for(int i=0; i<8; i++){
			long c = 0;
			for(int j=0; j<8; j++){
				long mulres = ((long) a[i] + c) * ((long) b[i]);
				row[j] = (int) mulres;
				c = mulres >>32;
			}
			c = 0;
			for(int j=i; j<8; j++){
				long longaddres = ((long)res[i]) + c + ((long)row[i+j]);
				res[j] = (int) longaddres;
				c = longaddres>>32;
			}
		}
	}

	/** simulate the multiplication, only do the RIGHT MOST 8 limbs */
	public void mul2(Fp others){
		int [] a = TEMP;
		for(int i=0; i<a.length; i++){
			a[i] = this.T[i];	
		}
		int [] b = others.T;
		int [] row = TEMP;
		int [] res = this.T;	
		//1. FLATTON
int a0 = a[0];
int b0 = b[0];
int res0 = 0;
int a1 = a[1];
int b1 = b[1];
int res1 = 0;
int a2 = a[2];
int b2 = b[2];
int res2 = 0;
int a3 = a[3];
int b3 = b[3];
int res3 = 0;
int a4 = a[4];
int b4 = b[4];
int res4 = 0;
int a5 = a[5];
int b5 = b[5];
int res5 = 0;
int a6 = a[6];
int b6 = b[6];
int res6 = 0;
int a7 = a[7];
int b7 = b[7];
int res7 = 0;
int a8 = a[8];
int b8 = b[8];
int res8 = 0;
int a9 = a[9];
int b9 = b[9];
int res9 = 0;
int a10 = a[10];
int b10 = b[10];
int res10 = 0;
int a11 = a[11];
int b11 = b[11];
int res11 = 0;
int a12 = a[12];
int b12 = b[12];
int res12 = 0;
int a13 = a[13];
int b13 = b[13];
int res13 = 0;
int a14 = a[14];
int b14 = b[14];
int res14 = 0;
int a15 = a[15];
int b15 = b[15];
int res15 = 0;
int row0 = 0;
int row1 = 0;
int row2 = 0;
int row3 = 0;
int row4 = 0;
int row5 = 0;
int row6 = 0;
int row7 = 0;
int row8 = 0;
int row9 = 0;
int row10 = 0;
int row11 = 0;
int row12 = 0;
int row13 = 0;
int row14 = 0;
int row15 = 0;

		long c = 0;
		long mulres = 0;
		long longaddres = 0;

		//UNROLLED
c = 0;
mulres = ((long)a0+c)*((long)b0);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a0+c)*((long)b0);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res0) + c + ((long)row0);
res0= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row1);
res1= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row2);
res2= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row3);
res3= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row4);
res4= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row5);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row6);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res0) + c + ((long)row7);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a1+c)*((long)b1);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a1+c)*((long)b1);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res1) + c + ((long)row2);
res1= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row3);
res2= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row4);
res3= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row5);
res4= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row6);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row7);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res1) + c + ((long)row8);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a2+c)*((long)b2);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a2+c)*((long)b2);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res2) + c + ((long)row4);
res2= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res2) + c + ((long)row5);
res3= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res2) + c + ((long)row6);
res4= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res2) + c + ((long)row7);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res2) + c + ((long)row8);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res2) + c + ((long)row9);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a3+c)*((long)b3);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a3+c)*((long)b3);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res3) + c + ((long)row6);
res3= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res3) + c + ((long)row7);
res4= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res3) + c + ((long)row8);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res3) + c + ((long)row9);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res3) + c + ((long)row10);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a4+c)*((long)b4);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a4+c)*((long)b4);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res4) + c + ((long)row8);
res4= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res4) + c + ((long)row9);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res4) + c + ((long)row10);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res4) + c + ((long)row11);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a5+c)*((long)b5);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a5+c)*((long)b5);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res5) + c + ((long)row10);
res5= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res5) + c + ((long)row11);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res5) + c + ((long)row12);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a6+c)*((long)b6);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a6+c)*((long)b6);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res6) + c + ((long)row12);
res6= (int)longaddres;
c = longaddres>>32;
longaddres = ((long)res6) + c + ((long)row13);
res7= (int)longaddres;
c = longaddres>>32;
c = 0;
mulres = ((long)a7+c)*((long)b7);
row0 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row1 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row2 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row3 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row4 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row5 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row6 = (int) mulres;
c=mulres>>32;
mulres = ((long)a7+c)*((long)b7);
row7 = (int) mulres;
c=mulres>>32;
c = 0;
longaddres = ((long)res7) + c + ((long)row14);
res7= (int)longaddres;
c = longaddres>>32;
this.T[0] = res0;
this.T[1] = res1;
this.T[2] = res2;
this.T[3] = res3;
this.T[4] = res4;
this.T[5] = res5;
this.T[6] = res6;
this.T[7] = res7;
this.T[8] = res8;
this.T[9] = res9;
this.T[10] = res10;
this.T[11] = res11;
this.T[12] = res12;
this.T[13] = res13;
this.T[14] = res14;
this.T[15] = res15;



	}


	public static void perfFpMul1(Fp [] arr, Configuration cfg){
		long start = System.currentTimeMillis();
		for(int i=1; i<arr.length; i++){
			arr[i].mul1(arr[0]);
		}
		long end= System.currentTimeMillis();
		System.out.println("arr[1000] is " + arr[1000].T[5]);
		System.out.println("Customized 256 Mmul1: " + (end-start) + " ms");
	}
	public static void perfFpMul2(Fp [] arr, Configuration cfg){
		long start = System.currentTimeMillis();
		for(int i=1; i<arr.length; i++){
			arr[i].mul2(arr[0]);
		}
		System.out.println("arr[1000] is " + arr[1000].T[5]);
		long end= System.currentTimeMillis();
		System.out.println("Customized 256 Mul2: " + (end-start) + " ms");
	}
}
