/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   FFT Profiler Class.
*	Author: Dr. CorrAuthor
*	Created: 05/01/2022
* *******************************************/
package cs.Employer.profiler;

import cs.Employer.zkregex.Tools;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;
import cs.Employer.poly.Bn254aFr;
import cs.Employer.poly.FFT;
import common.Utils;
import algebra.fft.FFTAuxiliary;
import algebra.fft.DistributedFFT; 
import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;
import java.math.BigInteger;
import configuration.Configuration;
import org.apache.spark.api.java.JavaPairRDD;
import scala.Tuple2;
import java.lang.RuntimeException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;

/** 
This class provides a number of profiling functions for
measuring the performance of FFT
*/
public class FFTProfiler{
	/** from BigInteger to Bn254aFr array */
	public static ArrayList<Bn254aFr> to_bn254afr(BigInteger [] arr){
		Bn254aFr zero = Bn254aFr.create_zero();
		ArrayList<Bn254aFr> al = new ArrayList<>(Collections.nCopies(arr.length, zero));
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigNum256 val = BigNum256.from_bi(arr[i].mod(fp.biN));
			al.set(i, new Bn254aFr(val));
		}
		return al;
		
	}
	public static Bn254aFr [] to_bn254afr_arr(BigInteger [] arr){
		Bn254aFr zero = Bn254aFr.create_zero();
		Bn254aFr [] al = new Bn254aFr [arr.length];
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigNum256 val = BigNum256.from_bi(arr[i].mod(fp.biN));
			al[i] = new Bn254aFr(val);
		}
		return al;
		
	}
	/** From Bn254aFr to DIZK's */
	public static ArrayList<BN254aFr> to_dizk_bn254afr(ArrayList<Bn254aFr> arr){
		ArrayList<BN254aFr> al = new ArrayList<>(Collections.nCopies(arr.size(), null));
		for(int i=0; i<arr.size(); i++){
			al.set(i, arr.get(i).to_dizk());
		}
		return al;
		
	}
	public static void profileAllFFT(Configuration cfg, int log_size){
		int k = log_size; //leads to one million
		int N = 1<<k; 
		System.out.println("PROFILE SerialFFT Size: " + N);
		ArrayList<Bn254aFr> al = Bn254aFr.randArr(N);
		
		Bn254aFr zero = Bn254aFr.create_zero();
		FFT<Bn254aFr> fft = new FFT<Bn254aFr>(zero);
		Bn254aFr omega = fft.getOmega(N);
		BN254aFr dizk_omega = omega.to_dizk();
/*
		cfg.beginLog("Old SerialFFT");
		FFTAuxiliary.serialRadix2FFT(al_dizk, dizk_omega);
		cfg.endLog("Old SerialFFT");
		cfg.beginLog("Recursive SerialFFT");
		fft.serialRadix2FFT(al, omega);
		cfg.endLog("New SerialFFT");
*/
/*
		cfg.beginLog("Recursive SerialFFT");
		ArrayList<Bn254aFr> ar_res2 = fft.serialRecursiveFFT(al);
		cfg.endLog("Recursive SerialFFT");
		
		cfg.beginLog("serialRecursiveJobFFT");
		fft.serialRecursiveJobFFT(al, cfg);
		cfg.endLog("serialRecursiveJobFFT");
*/
/*
		cfg.beginLog("DistributedRecursiveFFT");
		fft.distributedRecursiveJobFFT(al, cfg);
		cfg.endLog("DistributedRecursiveFFT");
*/

/*
		for(int bits=10; bits<20; bits++){
			int size = 1<<bits;
			ArrayList<Bn254aFr> input = Bn254aFr.randArr(size);
			long t1 = System.currentTimeMillis();
			int total = 100;
			for(int u= 0; u<total; u++){
				//fft = new FFT<Bn254aFr>(zero);
				fft.serialRecursiveFFT(input);
			}
			long t2 = System.currentTimeMillis();
			System.out.println("size: " + size + ": " + (t2-t1)/total + "ms");
		}
*/
/*
cfg.beginLog("SerialRecursiveFFT");
fft.serialRecursiveFFT(al);
cfg.endLog("SerialRecursiveFFT");
*/
		cfg.beginLog("DistributedDizkFFT");
		JavaPairRDD<Long,Bn254aFr> rdd = fft.arr_to_rdd(al, cfg);
		for(int i=0; i<10; i++){
			System.out.println("Iteration: i: " + i);
			long t1 = System.currentTimeMillis();
		 	rdd = fft.distributedDizkFFT(al.size(), rdd, cfg);
			long t2 = System.currentTimeMillis();
			System.out.println("Iteration " + i + " time: " + (t2-t1) + "ms");
		}
		ArrayList<Bn254aFr> res = fft.rdd_to_arr(rdd, cfg);
		cfg.endLog("DistributedDizkFFT");

	}


/*
	public static void profileDistributedFFT(Configuration cfg, int log_size){
		int k = log_size; //leads to one million
		int N = 1<<k; 
		BigInteger [] arr = Tools.randArrBi(256, N);
		System.out.println("PROFILE Distributed Size: " + N);
		ArrayList<Bn254aFr> al = FFTProfiler.to_bn254afr(arr);
		ArrayList<BN254aFr> al_dizk = FFTProfiler.to_dizk_bn254afr(al);
		Bn254aFr zero = Bn254aFr.create_zero();
		FFT<Bn254aFr> fft = new FFT<Bn254aFr>(zero);
		Bn254aFr omega = fft.getOmega(N);
		BN254aFr dizk_omega = omega.to_dizk();
		cfg.beginLog("Gen JavaPairRDD");
		JavaPairRDD<Long,BN254aFr> input = cfg.getSC().parallelizePairs(Utils.convertToPairs(al_dizk));
		long icount = input.count();
		cfg.endLog("Gen JavaPairRDD");
		cfg.beginLog("Gen JavaPairRDD Exp2");
		ArrayList<Tuple2<Long, ArrayList<BN254aFr>>> arr3 = new ArrayList<>();
		arr3.add(new Tuple2<>(100L, al_dizk));
		JavaPairRDD<Long,ArrayList<BN254aFr>> input2 = cfg.getSC().parallelizePairs(arr3);
		long lcount = input2.count();
		cfg.endLog("Gen JavaPairRDD Exp2");

		cfg.beginLog("Gen JavaPairRDD Exp3");
		cfg.getSC().parallelize(al_dizk).count();
		cfg.endLog("Gen JavaPairRDD Exp3");

		cfg.beginLog("OLD Distributed FFT");
		long rows = (long) (1<<(k/2));
		long cols = (long) N/rows;
		DistributedFFT.radix2FFT(input, rows, cols, al_dizk.get(0));
		cfg.endLog("OLD Distributed FFT");
		//cfg.beginLog("New SerialFFT");
		//fft.serialRadix2FFT(al, omega);
		//cfg.endLog("New SerialFFT");
	}
*/

}
