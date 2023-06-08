package cs.Employer.poly;
import cs.Employer.zkregex.Tools;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import java.math.BigInteger;
import cs.Employer.poly.BigNum256;

/**
 * Unit test for BigNum256.
 */
public class BigNum256Test 
{

	/** return samples for unit testing */
	public static BigInteger [] getSamples(){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		BigInteger one = new BigInteger("1");
		BigInteger [] arr = new BigInteger [] {
			new BigInteger("11972743258999954072608883967267172937197689892475318294109741798374968846003"), //mont -> N-1
			new BigInteger("11972743258999954072608883967267172937197689892475318294109741798374968846003"), //mont -> N-1
			new BigInteger("0"),
			new BigInteger("1"),
			new BigInteger("0"),
			new BigInteger("2147483647"), //2^31-1
			new BigInteger("2147483648"), //2^31
			new BigInteger("2147483649"), //2^31+1
			new BigInteger("4294967295"), //2^32-1
			new BigInteger("4294967296"), //2^32
			new BigInteger("4294967297"), //2^32+1
			new BigInteger("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16), //bn254 Fq modulus
			new BigInteger("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16), //bn254 Fr modulus
			b256.subtract(one),
			b256.subtract(one).subtract(one),
		};
		return arr;
	}
	public static BigNum256 [] getBigNum256Samples(){
		BigInteger [] samples = getSamples();
		BigNum256[] arr = new BigNum256 [samples.length];
		for(int i=0; i<arr.length; i++){
			arr[i] = BigNum256.from_bi(samples[i]);
		}
		return arr;
	}
    @Test
    public void from_to_BigInteger()
    {
		BigInteger [] arr = getSamples();
		for(int i=0; i<arr.length; i++){
			BigInteger bi = arr[i];	
			BigNum256 bn = BigNum256.from_bi(bi);
			BigInteger bi2 = bn.to_bi();
			if(!bi.equals(bi2)){
				fail("bi!=bi2. For case: "+i+". bi: "+bi+", bi2: "+bi2);
			}
		}
    }

	protected void test_add256_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		for(int i=0; i<arr.length; i++){
			BigInteger bi = arr[i];
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = new BigNum256(bn);
			bn.add256With(bn2);
			BigInteger bi2 = bi.add(bi).mod(b256);
			BigInteger bact = bn.to_bi();
			if(!bact.equals(bi2)){
				fail("Failed testAdd256 at case: " + i + ", BigNum256bit: " + 
					bact + ", expected: " + bi2);
			}
		}
	}
	protected void test_sub_8limbs_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		BigInteger zero = new BigInteger("0");
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi = arr[i].mod(b256);
			BigInteger bi2 = arr[i+1].mod(b256);
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = BigNum256.from_bi(bi2);
			long res_sign = bn.subWith_8limbs(bn2);

			BigInteger expected  = bi.subtract(bi2);
			long expected_sign = 0;
			if(expected.signum()==-1){
				expected_sign = 1;
			}
			if(res_sign!=expected_sign){
				fail("Failed testSubWith_8Limbs at case: " + i + ", actual sign: " + res_sign + ", expected_sign: " + expected_sign + ", input A: 0x" + bi.toString(16) + ", input B: 0x" + bi2.toString(16));
			}

			//COMPARE the absolute value instead
			BigNum256 bneg = new BigNum256();
			bneg.subWith_8limbs(bn);
			BigInteger bzero = new BigInteger("0");
			BigInteger act_abs = res_sign==0? bn.to_bi(): bneg.to_bi();
			BigInteger expected_abs = res_sign==0? expected: bzero.subtract(expected); 
			if(!act_abs.equals(expected_abs)){
				fail("Failed testSubWith_8Limbs at case: " + i + ", BigNum256bit(abs): 0x" + act_abs.toString(16) + ", expected(abs): 0x" + expected_abs.toString(16) + ", input A: 0x" + bi.toString(16) + ", input B: 0x" + bi2.toString(16));
			}
		}
	}
	protected void test_abssub_8limbs_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		BigInteger zero = new BigInteger("0");
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi = arr[i].mod(b256);
			BigInteger bi2 = arr[i+1].mod(b256);
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = BigNum256.from_bi(bi2);
			long res_sign = bn.abssubWith_8limbs(bn2);

			BigInteger expected  = bi.subtract(bi2);
			long expected_sign = 0;
			if(expected.signum()==-1){
				expected_sign = 1;
			}
			if(res_sign!=expected_sign){
				fail("Failed testAbsSubWith_8Limbs at case: " + i + ", actual sign: " + res_sign + ", expected_sign: " + expected_sign + ", input A: 0x" + bi.toString(16) + ", input B: 0x" + bi2.toString(16));
			}

			//COMPARE the absolute value instead
			BigInteger act_abs = bn.to_bi();
			BigInteger bzero = new BigInteger("0");
			BigInteger expected_abs = res_sign==0? expected: bzero.subtract(expected); 
			if(!act_abs.equals(expected_abs)){
				fail("Failed testAbsSubWith_8Limbs at case: " + i + ", BigNum256bit(abs): 0x" + act_abs.toString(16) + ", expected(abs): 0x" + expected_abs.toString(16) + ", input A: 0x" + bi.toString(16) + ", input B: 0x" + bi2.toString(16));
			}
		}
	}
	protected void test_neg_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");
		for(int i=0; i<arr.length; i++){
			BigInteger bi = arr[i].mod(b256);
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = new BigNum256(bn);
			bn2.neg_8limbs();
			BigNum256 bn3 = new BigNum256(bn2);
			bn2.addWith_8limbs(bn);
			BigInteger bres = bn2.to_bi();
			if(!zero.equals(bres)){
				fail("Failed testNeg at case: " + i + ", num + ITS neg: " + 
					bres.toString(16) + ", expected: 0. Input a: " + bi + ", generated neg: "
					+ bn3.to_bi().toString(16));
			}
		}
	}
	protected void test_add_8limbs_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		BigInteger one = new BigInteger("1");
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi = arr[i].mod(b256);
			BigInteger bi2 = arr[i+1].mod(b256);
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = BigNum256.from_bi(bi2);
			long carry = bn.addWith_8limbs(bn2);

			BigInteger bexpect= bi.add(bi2).mod(b256);
			BigInteger bact = bn.to_bi();
			long carry_expected = 0;
			if(!bi.add(bi2).equals(bexpect)){
				carry_expected = 1;
			}
			if(!bact.equals(bexpect)){
				System.out.println("DEBUG USE 100 ---");
				bn.dump();
				fail("Failed testAdd8_limbs at case: " + i + ", BigNum256bit: " + bact + ", expected: " + bi2 + ", INPUT a: " + bi + ", INPUT b: " + bi2);
			}
			if(carry!=carry_expected){
				fail("Failed testAdd8_limbs at case: " + i + ", carry: " + carry + ", carry_expected: " + carry_expected);
			}
		}
	}
	protected void test_mul256_worker(BigInteger [] arr){
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi = arr[i];
			BigInteger bi2 = arr[i+1];
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = BigNum256.from_bi(bi2);
			bn.mul256With(bn2);
			BigInteger bi_exp = bi.multiply(bi2).mod(b256);
			BigInteger bact = bn.to_bi();
			if(!bact.equals(bi_exp)){
				fail("Failed testMul256 at case: " + i + ", BigNum256bit: " + 
					bact.toString(16) + ", expected: " + bi_exp.toString(16));
			}
		}
	}
	protected void test_mul512_worker(BigInteger [] arr){
		BigInteger b512= new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096"); //2^512
		BigInteger b256= new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936"); //2^256
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi = arr[i].mod(b256);
			BigInteger bi2 = arr[i+1].mod(b256);
			BigNum256 bn = BigNum256.from_bi(bi);
			BigNum256 bn2 = BigNum256.from_bi(bi2);
			bn.mul512With(bn2);
			BigInteger bi_exp = bi.multiply(bi2).mod(b512);
			BigInteger bact = bn.to_bi512();
			if(!bact.equals(bi_exp)){
				fail("Failed testMul512 at case: " + i + ", input A: " + bi + ",input B: " + bi2 + ", Result BigNum512: " + bact + ", expected: " + bi_exp);
			}
		}
	}
	@Test
	public void testAdd256(){
		BigInteger [] arr = getSamples();
		test_add256_worker(arr);
	} 
	@Test
	public void randtestAdd256(){
		BigInteger [] arr = Tools.randArrBi(511, 10);
		test_add256_worker(arr);
	} 
	@Test
	public void testNeg(){
		BigInteger [] arr = getSamples();
		test_neg_worker(arr);
	} 
	@Test
	public void randtestNeg(){
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_neg_worker(arr);
	} 
	@Test
	public void testAbsNeg(){
		BigInteger [] arr = getSamples();
		test_abssub_8limbs_worker(arr);
	} 
	@Test
	public void randtestAbsNeg(){
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_abssub_8limbs_worker(arr);
	} 
	@Test
	public void testSub(){
		BigInteger [] arr = getSamples();
		test_sub_8limbs_worker(arr);
	} 
	@Test
	public void randtestSub8Limbs(){
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_sub_8limbs_worker(arr);
	} 
	@Test
	public void testAdd8limbs(){
		BigInteger [] arr = getSamples();
		test_add_8limbs_worker(arr);
	} 
	@Test
	public void randtestAdd8limbs(){
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_add_8limbs_worker(arr);
	} 
	@Test
	public void testMul256(){
		BigInteger [] arr = getSamples();
		test_mul256_worker(arr);
	} 
	@Test
	public void randtestMul256(){
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_mul256_worker(arr);
	} 
	@Test
	public void testMul512(){
		BigInteger [] arr = getSamples();
		test_mul512_worker(arr);
	} 
	@Test
	public void randtestMul512(){
		BigInteger [] arr = Tools.randArrBi(256, 100000);
		test_mul512_worker(arr);
	} 
}
