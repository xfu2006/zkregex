/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	LongElement Utility class
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import util.Util;
import circuit.auxiliary.LongElement;
import java.math.BigInteger;

public class LongEleUtil {
	/// Convert hexString to a seto of wires of num_bits/8 elements
	/// Start setting Wire values from idxStart
	/// Throw exception if the number if out of range
	/// num_bits has to be multiple of 8
	public static void setLongInputWires(CircuitEvaluator evaluator, Wire [] inputs, int idxStart, String hexString, int num_bits) throws Exception{
		BigInteger val = new BigInteger(hexString, 16);
		setLongInputWires(evaluator, inputs, idxStart, val, num_bits);
	}

	/// Convert hexString to a seto of wires of num_bits/8 elements
	/// Start setting Wire values from idxStart
	/// Throw exception if the number if out of range
	/// num_bits has to be multiple of 8
	public static void setLongInputWires(CircuitEvaluator evaluator, Wire [] inputs, int idxStart, BigInteger val, int num_bits) throws Exception{
		//1. split into integer array
		int unitsize= LongElement.CHUNK_BITWIDTH;
		if(num_bits%unitsize!=0){throw new Exception("num_bits not multiple of CHUNK_BITWIDTH!");}
		int num_segs = num_bits/unitsize;
		BigInteger [] arrV = Util.split(val, num_segs, LongElement.CHUNK_BITWIDTH);  
		if(arrV.length!=num_segs) {throw new Exception("arrV.length: " + arrV.length + " != num_segs: " + num_segs);}
		if(idxStart+num_segs>inputs.length){throw new Exception("idxStart+numBytes: " + (idxStart+num_segs) + "> inputs.length: " + inputs.length);}

		//2. set up the inputs wire
		for(int i=0; i<num_segs; i++){
			evaluator.setWireValue(inputs[i+idxStart], arrV[i]);
		}
	}

	/// Return a set of CHUNK values as the result of split
	public static BigInteger [] getChunks(BigInteger val, int num_bits) throws Exception{
		//1. split into integer array
		int unitsize= LongElement.CHUNK_BITWIDTH;
		if(num_bits%unitsize!=0){throw new Exception("num_bits not multiple of CHUNK_BITWIDTH!");}
		int num_segs = num_bits/unitsize;
		BigInteger [] arrV = Util.split(val, num_segs, LongElement.CHUNK_BITWIDTH);  
		if(arrV.length!=num_segs) {throw new Exception("arrV.length: " + arrV.length + " != num_segs: " + num_segs);}
		return arrV;
	}
}
