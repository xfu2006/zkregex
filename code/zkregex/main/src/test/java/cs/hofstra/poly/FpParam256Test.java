package cs.Employer.poly;
import cs.Employer.zkregex.Tools;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import java.math.BigInteger;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;

/**
 * Unit test for BigNum256.
 */
public class FpParam256Test
{

	protected void logical_mont_worker(BigInteger [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigInteger inp = arr[i].mod(fp.biN); //it has be smaller than N
			BigNum256 a = BigNum256.from_bi(inp);
			BigNum256 a2 = new BigNum256(a);
			fp.to_mont_logical(a);
			fp.backfrom_mont_logical(a);
			if(!a.equals(a2)){ 
				fail("logical to_from mont fails at case " + i + ", a: " + a2.to_bi());
			}
		}
	}

	protected void test_to_mont_worker(BigInteger [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigNum256 a = BigNum256.from_bi(arr[i]);
			BigNum256 a2 = new BigNum256(a);
			BigNum256 a3 = new BigNum256(a);
			fp.to_mont_logical(a);
			fp.to_mont(a2);
			if(!a.equals(a2)){ 
				fail("to_mont fails at case " + i + ", a: " + a3.to_bi() + ", logical produces: " + a2.to_bi() + ", to_mont produces: " + a.to_bi());
			}
		}
	}

	protected void test_from_mont_worker(BigInteger [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigNum256 a = BigNum256.from_bi(arr[i]);
			BigNum256 a2 = new BigNum256(a);
			BigNum256 a3 = new BigNum256(a);
			fp.backfrom_mont_logical(a);
			fp.backfrom_mont(a2);
			if(!a.equals(a2)){ 
				fail("from_mont fails at case " + i + ", a: " + a3.to_bi() + ", logical produces: " + a2.to_bi() + ", to_mont produces: " + a.to_bi());
			}
		}
	}

	// given any two input, conver to mon presentation using logical mont
	// add it using mon_add
	// convert it back using backfrom_mon and test the result
	protected void test_mon_add_worker(BigInteger [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi1 = arr[i].mod(fp.biN);
			BigInteger bi2 = arr[i+1].mod(fp.biN);
			BigInteger bi_exp = bi1.add(bi2).mod(fp.biN);

			BigNum256 a = BigNum256.from_bi(bi1);
			BigNum256 b = BigNum256.from_bi(bi2);
			fp.to_mont_logical(a);
			fp.to_mont_logical(b);
			BigNum256 c = new BigNum256();
			fp.MonAdd(a, b, c);
			fp.backfrom_mont(c);
			BigInteger bi_act = c.to_bi();
			if(!bi_act.equals(bi_exp)){ 
				fail("MonAdd fails at case " + i + ", a: " + bi1.toString(16) + ", b: " + bi2.toString(16) + ", actual: " + bi_act.toString(16) + ", expected:  " + bi_exp.toString(16));
			}
		}
	}


	// given any two input, conver to mon presentation using logical mont
	// sub it using mon_sub
	// convert it back using backfrom_mon and test the result
	protected void test_mon_sub_worker(BigInteger [] arr){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi1 = arr[i].mod(fp.biN);
			BigInteger bi2 = arr[i+1].mod(fp.biN);
			BigInteger bi_exp = bi1.subtract(bi2).add(fp.biN).mod(fp.biN);

			BigNum256 a = BigNum256.from_bi(bi1);
			BigNum256 b = BigNum256.from_bi(bi2);
			fp.to_mont_logical(a);
			fp.to_mont_logical(b);
			BigNum256 c = new BigNum256();
			fp.MonSub(a, b, c);
			fp.backfrom_mont(c);
			BigInteger bi_act = c.to_bi();
			if(!bi_act.equals(bi_exp)){ 
				fail("MonSub fails at case " + i + ", a: " + bi1.toString(16) + ", b: " + bi2.toString(16) + ", actual: " + bi_act.toString(16) + ", expected:  " + bi_exp.toString(16));
			}
		}
	}

	/** test if logical mont_gomery works */
    @Test
    public void logical_mont()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		logical_mont_worker(arr);
    }

	/** test if logical mont_gomery works, randomly */
    @Test
    public void logical_mont_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		logical_mont_worker(arr);
    }

	/* test to_mont */
    @Test
    public void test_to_mont()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_to_mont_worker(arr);
    }

	/** test if logical mont_gomery works, randomly */
    @Test
    public void test_to_mont_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_to_mont_worker(arr);
    }

	/* test from_mont */
    @Test
    public void test_from_mont()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_from_mont_worker(arr);
    }

	/** test if logical mont_gomery works, randomly */
    @Test
    public void test_from_mont_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_from_mont_worker(arr);
    }



	/** test logical MonPro */
	@Test
	public void randtest_logical_MonPro(){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<10; i++){
			//1. generate expected field element as multiplication
			BigNum256 a = fp.rand_fp();
			BigNum256 b = fp.rand_fp();

			BigNum256 expected = new BigNum256();
			fp.logical_mul(a, b, expected);
			String part1 = "a: " + a.to_bi().toString() + ", b: " + b.to_bi().toString() + ", expected: " + expected.to_bi().toString();

			//2. use Montgomery Reducction
			fp.to_mont_logical(a);
			fp.to_mont_logical(b);
			BigNum256 act = new BigNum256();
			fp.logical_MonPro(a, b, act);
			fp.backfrom_mont_logical(act);
			String all = part1 += ", actual: " + act.to_bi().toString();
			if(!expected.equals(act)){
				fail("test_logical_MonPro failed at: " + all);
			}
		
		}
	}

	/** test real MonPro */
	@Test
	public void randtest_MonPro(){
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<100; i++){
			//1. generate expected field element as multiplication
			BigNum256 a = fp.rand_fp();
			BigNum256 b = fp.rand_fp();
//a = BigNum256.from_bi(new BigInteger("12764633429516502823376213550453576150632277469542325464234463778897133888862"));
//b = BigNum256.from_bi(new BigInteger("16951215003376253443625067456671949628440248827128900699916199557617678468244"));
//			a = BigNum256.from_bi(new BigInteger("1"));
//			b = BigNum256.from_bi(new BigInteger("1"));

			BigNum256 expected = new BigNum256();
			BigNum256 act = new BigNum256();
			fp.logical_MonPro(a, b, expected);
			fp.MonPro(a, b, act);
			String all = "expected: " + expected.to_bi().toString() +  
				", actual: " + act.to_bi().toString() ; 
			if(!expected.equals(act)){
				System.out.println("a: " + a.to_bi());
				System.out.println("b: " + b.to_bi());
				System.out.println("--- Expected Dump ----");
				expected.dump();
				System.out.println("--- Actual Dump ---");
				act.dump();
				fail("FAILED MonPro: " + all); 
			}
		
		}
	}

    @Test
    public void test_add_mon()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_mon_add_worker(arr);
    }
    @Test
    public void test_add_mon_rand()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_mon_add_worker(arr);
    }
    @Test
    public void test_sub_mon()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_mon_sub_worker(arr);
    }
    @Test
    public void test_sub_mon_rand()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_mon_sub_worker(arr);
    }
}

