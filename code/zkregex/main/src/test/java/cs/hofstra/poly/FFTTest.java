package cs.Employer.poly;

import cs.Employer.zkregex.Tools;
import cs.Employer.profiler.FFTProfiler;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import org.junit.Test;
import java.math.BigInteger;
import cs.Employer.poly.BigNum256;
import configuration.Configuration;
import cs.Employer.poly.FpParam256;
import cs.Employer.poly.Bn254aFr;
import java.util.Random;
import java.util.ArrayList;
import java.util.Collections;
import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;
import algebra.fft.FFTAuxiliary;

/**
 * Unit test for FFT Operations
 */
public class FFTTest 
{
	protected static Configuration cfg;

	@BeforeClass
	public static void before() throws Exception{
		cfg = Tools.buildLocalConfig1();
	}

	@AfterClass
	public static void after() throws Exception{
		Tools.stopSC(cfg);
	}
	
    @Test
    public void test_FFTAlgs()
    {
		int k = 10; //leads to one million
		int N = 1<<k; 
		BigInteger [] arr = Tools.randArrBi(256, N);
		ArrayList<Bn254aFr> al = FFTProfiler.to_bn254afr(arr);
		ArrayList<Bn254aFr> al2 = FFTProfiler.to_bn254afr(arr);
		ArrayList<Bn254aFr> al3 = FFTProfiler.to_bn254afr(arr);
		ArrayList<Bn254aFr> al4 = FFTProfiler.to_bn254afr(arr);
		ArrayList<Bn254aFr> al5 = FFTProfiler.to_bn254afr(arr);
		ArrayList<BN254aFr> al_dizk = FFTProfiler.to_dizk_bn254afr(al);
		Bn254aFr zero = Bn254aFr.create_zero();
		FFT<Bn254aFr> fft = new FFT<Bn254aFr>(zero);
		Bn254aFr omega = fft.getOmega(N);
		BN254aFr dizk_omega = omega.to_dizk();
		fft.serialRadix2FFT(al, omega);
		FFTAuxiliary.serialRadix2FFT(al_dizk, dizk_omega);
		check_eq("serialRadix2FFT", al, al_dizk);
		//check the recursive one
		ArrayList<Bn254aFr> alres = fft.serialRecursiveFFT(al2);
		check_eq("serialRecursiveFFT", alres, al_dizk);

		ArrayList<Bn254aFr> alres3= fft.distributedRecursiveJobFFT(al3, cfg);
		check_eq("distributedRecursiveFFT", alres3, al_dizk);

		ArrayList<Bn254aFr> alres4= fft.serialRecursiveJobFFT(al4, cfg);
		check_eq("serialRecursiveJobFFT", alres4, al_dizk);

		ArrayList<Bn254aFr> alres5= fft.distributedDizkFFT_wrapper(al5, cfg);
		check_eq("distributedDizkFFT", alres5, al_dizk);
		 
    }
	//----------------------------------------------
	// region protected operations
	//----------------------------------------------
	protected void check_eq(String prefix, ArrayList<Bn254aFr> arr1, ArrayList<BN254aFr> arr2){
		for(int i=0; i<arr1.size(); i++){
			BigInteger bi1 = arr1.get(i).toBigInteger();
			BigInteger bi2 = arr2.get(i).toBigInteger();
			if(!bi1.equals(bi2)){
				fail(prefix + ": check_eq fails at index: " + i + ", Bn254aFr: " + bi1.toString(16) + ", dizk_BN254aFr: " + bi2.toString(16));
			}
		}
	}
	//----------------------------------------------
	// end region protected operations
	//----------------------------------------------

}

