/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/

/*************************************************************
  *** Deprecated ***
  This class runs a generator and generates the circuit files
  It invokes libsnark to generate the R1CS files for each platform
  For each circuit, it will generate (e.g., for LIBSNARK)
  cirname.arith.LIBSNARK (circuit file)
  cirname.in.LIBSNARK (input values)
  cirname.R1CS.LIBSNARK (the R1CS files)
* *************************************************************/
package za_interface;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;

import za_interface.generators.basic_ops.*;
import za_interface.generators.gadgets.*;

public class GeneratorDriver{
	/** MACRO definition of generator IDs */
	public static final int ADD = 0;
	public static final int MUL = 1;
	public static final int ZEROP = 2;
	public static final int SHA2 = 3;
	public static final int LongEleAdd= 4;
	public static final int LongEleAddEq= 5;
	public static final int LongEleMul= 6;
	public static final int LongEleMulEq= 7;
	public static final int LongEleModEq= 8;
	public static final int Pow16= 9;
	public static final int Pow128= 10;
	public static final int Pow1024= 11;
	public static final int SHA2Path= 12;

	/** Some frequently used list */
	public static final int [] LIST_FULL= {ADD, MUL, ZEROP, SHA2, LongEleAdd, LongEleAddEq, LongEleMul, LongEleMulEq, LongEleModEq, Pow16, Pow128, SHA2, SHA2Path};
	public static final int [] LIST_SIMPLE_TEST = {SHA2};
	
	/** Given integer index, generates the generator instance */
	public CircuitGenerator createGenerator(int i){
		if(i==ADD){ return new AddGen(); }
		else if(i==MUL) {return new MulGen();}
		else if(i==ZEROP) {return new ZeropGen();}
		else if(i==SHA2) {return new SHA2();}
		else if(i==LongEleAdd) {return new LongEleAddGen();}
		else if(i==LongEleAddEq) {return new LongEleAddEqGen();}
		else if(i==LongEleMul) {return new LongEleMulGen();}
		else if(i==LongEleMulEq) {return new LongEleMulEqGen();}
		else if(i==LongEleModEq) {return new LongEleModEqGen();}
		else if(i==Pow16) {return new Pow16();}
		else if(i==Pow128) {return new Pow128();}
		else if(i==Pow1024) {return new Pow1024();}
		else if(i==SHA2Path) {return new SHA2Path();}
		else{return null;}
	}

	public static void resetFieldOrder(BigInteger new_field_order){
		Config.FIELD_PRIME= new_field_order;
		Config.LOG2_FIELD_PRIME = Config.FIELD_PRIME.toString(2).length();
		System.out.println("RESET field order to " + Config.FIELD_PRIME);
	}

	/**
	  Generates the r1cs for the prime field info.  The file names will be suffixed with the prime field's name.
		Note: generator can ONLY BE used once, calling genSampleInput
	will screw its currentWireID etc. So, when the generator is passed,
	its prime order is already set up in ZaInterface.
	*/
	public void genr1cs(int generator_id, PrimeFieldInfo info){
		resetFieldOrder(info.order);
		CircuitGenerator generator = createGenerator(generator_id);
		System.out.println("Generate R1CS for: " + generator.getName() + ", for platform: " + info.name + "\n");
		if(generator==null){
			System.err.println("There is NO generator with id: " + generator_id);
			return;
		}
		String dirpath = "circuits";
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles(dirpath, info.name);
		generator.genR1cs(info);
	}

}
