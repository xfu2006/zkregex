package cs.Employer.poly;
import cs.Employer.zkregex.Tools;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import java.math.BigInteger;
import cs.Employer.poly.BigNum256;
import cs.Employer.poly.FpParam256;
import cs.Employer.poly.Bn254aFr;
import java.util.Random;
import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;

/**
 * Unit test for Field Element for Bn254aFr
 */
public class Bn254aFrTest
{

	protected void test_constructor_worker(BigInteger [] arr){
/*
//REMOVE LATER ------------
Bn254aFr a1 = Bn254aFr.create_zero();
Bn254aFr b = a1.multiplicativeGenerator();
System.out.println("gen is: " + b);
//REMOVE LATER ------------ ABOVE
*/
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigNum256 a = BigNum256.from_bi(arr[i].mod(fp.biN));
			BigNum256 a2 = new BigNum256(a);
			Bn254aFr fr = new Bn254aFr(a);
			BigInteger aexp = fr.back_from_mont();
			BigInteger act = a2.to_bi();
			if(!act.equals(aexp)){ 
				fail("Bn254Fr constructor test fails case: " + i + ",  input: " + aexp + ", actual after back_from_mont: " + act);
			}
		}
	}
	@Test 
	public void test_construct(){
		long [] arr = new long [] {
			0x0L, 0x1L, 0x80000000L, 0x7FFFFFFFL, 0x8000000000000000L,
			0xFFFFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFEL, 0x1000000000000000L,
			0x7FFFFFFFFFFFFFFFL
		};
		for(int i=0; i<arr.length; i++){
			BigInteger bi = BigInteger.valueOf(arr[i]);
			BigNum256 bn = BigNum256.from_bi(bi);
			Bn254aFr fr1 = new Bn254aFr(bn);
			Bn254aFr fr2 = fr1.construct(arr[i]);
			if(!fr1.equals(fr2)){
				fail("construct() fails for case: " + i + ", input: " + Long.toHexString(arr[i]) + ", actual: " + fr1.value.to_bi().toString(16) + ", expected: " + fr2.value.to_bi().toString(16));
			}
		}
	}

	/** test compatibility with DIZK functions */
	@Test
	public void from_to_BN254aFr(){
		BN254aFr fac = new BN254aFr(new BigInteger("0"));
		for(int i=0; i<10; i++){
			BN254aFr dizk_ele = fac.random(null, null);
			Bn254aFr my_ele = Bn254aFr.from_dizk(dizk_ele);
			BN254aFr dizk_ele2 = my_ele.to_dizk();
			if(!dizk_ele.equals(dizk_ele2)){
				fail("from_to_dizk fails at input: " + dizk_ele + ", dizk_ele2: " + dizk_ele2);
			}	
		}
	}

    @Test
    public void test_toBigInteger()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		FpParam256 fp = FpParam256.createBN254aParam();
		for(int i=0; i<arr.length; i++){
			BigInteger bi = arr[i].mod(fp.biN);
			BigNum256 bn = BigNum256.from_bi(bi);
			Bn254aFr fr = new Bn254aFr(bn);
			BigInteger bi2 = fr.toBigInteger();
			if(!bi.equals(bi2)){
				fail("toBigInteger failed at case: " + i + ", bi: " +
					bi.toString(16) + ", bi2: " + bi2.toString(16));
			}	
		}
		Bn254aFr fac = new Bn254aFr(BigNum256.from_bi(new BigInteger("100")));
		Bn254aFr z0 = fac.zero();
		Bn254aFr o1 = fac.one();
		z0.addWith(o1);
		if(!z0.equals(fac.ONE)){
			fail("fails zero() and one(): z0: " + z0.toBigInteger() + ", one: " + o1.toBigInteger());
		}
    }

	@Test
	public void testRootOfUnity(){
		Random rand  = new Random();
		Bn254aFr fac = Bn254aFr.create_zero();
		for(int i=1; i<63; i++){
			long order = 1L << i;
			Bn254aFr r = fac.rootOfUnity(order); 
			Bn254aFr o = r.pow(order);
			if(!o.equals(fac.ONE)){
				fail("testRootOfUnit fails for input: " + order + ", root of unity: " + r + ", root^order: " + o);
			}
		}
	}

	//bTestImm: whether to test the immutable version (operand 1 is NOT changed)
	//op 0: mul, op 1: add, op 2:  sub, op 3: square, op 4: inverse, op 5: neg
	protected void test_op_worker_common(BigInteger [] arr, boolean bTestImm, int op){
		FpParam256 fp = FpParam256.createBN254aParam();
		BigInteger zero = new BigInteger("0");
		for(int i=0; i<arr.length-1; i++){
			BigInteger bi1 = arr[i].mod(fp.biN);
			BigInteger bi2 = arr[i+1].mod(fp.biN);
			BigInteger bi_exp;
			String sOp = "";	
			if(op==0){
 				bi_exp = bi1.multiply(bi2).mod(fp.biN);
				sOp = "Mul";
			}else if(op==1){
 				bi_exp = bi1.add(bi2).mod(fp.biN);
				sOp = "Add";
			}else if(op==2){
 				bi_exp = bi1.subtract(bi2).mod(fp.biN);
				sOp = "Sub";
			}else if(op==3){
 				bi_exp = bi1.multiply(bi1).mod(fp.biN);
				sOp = "Square";
			}else if(op==4){
				if(bi1.signum()==0){
 					bi_exp = new BigInteger("0");
				}else{
 					bi_exp = bi1.modInverse(fp.biN);
				}
				sOp = "Inverse";
			}else if(op==5){
 				bi_exp = zero.subtract(bi1).mod(fp.biN);
				sOp = "Negate";
			}else{
				throw new RuntimeException("op: " + op + " not supported!");
			}

			BigNum256 a1 = BigNum256.from_bi(bi1);
			BigNum256 a2 = BigNum256.from_bi(bi2);
			Bn254aFr fr1 = new Bn254aFr(a1);
			Bn254aFr fr2 = new Bn254aFr(a2);
			Bn254aFr fr3;
			if(bTestImm){
				if(op==0){
					fr3 = fr1.mul(fr2);
				}else if(op==1){
					fr3 = fr1.add(fr2);
				}else if(op==2){
					fr3 = fr1.sub(fr2);
				}else if(op==3){
					fr3 = fr1.square();
				}else if(op==4){
					fr3 = fr1.inverse();
				}else if(op==5){
					fr3 = fr1.negate();
				}else{
					throw new RuntimeException("op: " + op + " not supported!");
				}
			}else{
				if(op==0){
					fr3 = fr1;
					fr1.mulWith(fr2);
				}else if(op==1){
					fr3 = fr1;
					fr1.addWith(fr2);
				}else if(op==2){
					fr3 = fr1;
					fr1.subWith(fr2);
				}else if(op==3){
					fr3 = fr1;
					fr1.squareWith();
				}else if(op==4){
					fr3 = fr1;
					fr3.inverseWith();
				}else if(op==5){
					fr3 = fr1;
					fr3.negateWith();
				}else{
					throw new RuntimeException("op: " + op + " not supported!");
				}
			}
			BigInteger bi_act = fr3.back_from_mont();
			BigInteger bi_fr1 = fr1.back_from_mont();
			BigInteger bi_fr2 = fr2.back_from_mont();
			String sAll= 
			"Input1: " + bi1.toString(16) +
			", Input2: " + bi2.toString(16) +
			", bExpected : " + bi_exp.toString(16) +
			", bActual: " + bi_act.toString(16) +
			", bi_fr1: " + bi_fr1.toString(16) +
			", bi_fr2: " + bi_fr2.toString(16);
			if(!bi_act.equals(bi_exp)){ 
				fail("FAILED " + sOp + "(): bi_act !=bi_exp: " + sAll);
			}
			if(bTestImm){
				if(!bi_fr1.equals(bi1)){
					fail("FAILED: fr1 changed after " + sOp + "  "+ sAll);
				}
				if(!bi_fr2.equals(bi2)){
					fail("FAILED: fr2 changed after " + sOp + " " + sAll);
				}
			}
		}
	}

	protected void test_mul_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 0); //0 for mul 
	}

	protected void test_add_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 1); //1 for add 
	}

	protected void test_sub_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 2); //2 for sub 
	}

	protected void test_square_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 3); //3 for square 
	}

	protected void test_inverse_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 4); //4 for inverse 
	}

	protected void test_negate_worker_common(BigInteger [] arr, boolean bTestImm){
		test_op_worker_common(arr, bTestImm, 5); //5 for negate 
	}



	protected void test_mul_worker(BigInteger [] arr){
			test_mul_worker_common(arr, true);
	}
	protected void test_mulWith_worker(BigInteger [] arr){
			test_mul_worker_common(arr, false);
	}

	protected void test_add_worker(BigInteger [] arr){
			test_add_worker_common(arr, true);
	}
	protected void test_addWith_worker(BigInteger [] arr){
			test_add_worker_common(arr, false);
	}

	protected void test_sub_worker(BigInteger [] arr){
			test_sub_worker_common(arr, true);
	}
	protected void test_subWith_worker(BigInteger [] arr){
			test_sub_worker_common(arr, false);
	}

	protected void test_square_worker(BigInteger [] arr){
			test_square_worker_common(arr, true);
	}
	protected void test_squareWith_worker(BigInteger [] arr){
			test_square_worker_common(arr, false);
	}

	protected void test_inverse_worker(BigInteger [] arr){
			test_inverse_worker_common(arr, true);
	}
	protected void test_inverseWith_worker(BigInteger [] arr){
			test_inverse_worker_common(arr, false);
	}

	protected void test_negate_worker(BigInteger [] arr){
			test_negate_worker_common(arr, true);
	}
	protected void test_negateWith_worker(BigInteger [] arr){
			test_negate_worker_common(arr, false);
	}


    @Test
    public void test_constructor()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_constructor_worker(arr);
    }
    @Test
    public void test_constructor_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 10);
		test_constructor_worker(arr);
    }
    @Test
    public void test_mul()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_mul_worker(arr);
    }
    @Test
    public void test_mul_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_mul_worker(arr);
    }

    @Test
    public void test_mulWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_mulWith_worker(arr);
    }
    @Test
    public void test_mulWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_mulWith_worker(arr);
    }


    @Test
    public void test_add()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_add_worker(arr);
    }
    @Test
    public void test_add_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_add_worker(arr);
    }

    @Test
    public void test_addWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_addWith_worker(arr);
    }
    @Test
    public void test_addWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_subWith_worker(arr);
    }

    @Test
    public void test_sub()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_sub_worker(arr);
    }
    @Test
    public void test_sub_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_sub_worker(arr);
    }

    @Test
    public void test_subWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_subWith_worker(arr);
    }
    @Test
    public void test_subWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_subWith_worker(arr);
    }

    @Test
    public void test_square()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_square_worker(arr);
    }
    @Test
    public void test_square_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_square_worker(arr);
    }


    @Test
    public void test_squareWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_squareWith_worker(arr);
    }
    @Test
    public void test_squareWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_squareWith_worker(arr);
    }

    @Test
    public void test_inverse()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_inverse_worker(arr);
    }
    @Test
    public void test_inverse_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_inverse_worker(arr);
    }


    @Test
    public void test_inverseWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_inverseWith_worker(arr);
    }
    @Test
    public void test_inverseWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_inverseWith_worker(arr);
    }
    @Test
    public void test_negate()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_negate_worker(arr);
    }
    @Test
    public void test_negate_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_negate_worker(arr);
    }


    @Test
    public void test_negateWith()
    {
		BigInteger [] arr = BigNum256Test.getSamples();
		test_negateWith_worker(arr);
    }
    @Test
    public void test_negateWith_random()
    {
		BigInteger [] arr = Tools.randArrBi(256, 100);
		test_negateWith_worker(arr);
    }
}

