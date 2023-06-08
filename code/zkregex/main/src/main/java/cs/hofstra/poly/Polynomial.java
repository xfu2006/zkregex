/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Polynomial Class.
*	Author: Dr. CorrAuthor
*	Created: 04/12/2022
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

/**
	Polynomial class. Supports polynomial add,mul,div,mod.
This is a WRAPPER of the FFT and Lagrange operations available
in the dizk package. All operations except add are nlog(n).
Degrees will be rounded up to 2^k.
Note: this class needs SPARK-2.1 to run.
*/
public class Polynomial<FieldT extends AbstractFieldElementExpanded<FieldT>> {

	//--------------------------------
	//region DATA Members
	//--------------------------------
	/** needs to be rounded to 2^k */
	protected int degree;  
	/** co-effiicents */
	protected JavaPairRDD<Long, FieldT> coefs;
	/** point representation. Each point is represented
		as (omega_i, points[i]) */
	protected JavaPairRDD<Long, FieldT>  points;
	/** zero */
	protected FieldT zero;
	/** config */
	protected Configuration config;
	/** enum type ADD */
	protected static final int ADD = 1;
	/** enum type MUL */
	protected static final int MUL = 2;
	//--------------------------------
	//endregion DATA MEMBERS
	//--------------------------------

	//--------------------------------
	//region PUBLIC Methods
	//--------------------------------

	/** Constructor. Takes a list of coefficients. coefs[0] is the
		coefs for the least weighted item, i.e.,
		p(x) = coefs[0] + coefs[1]*x + ... coefs[n]*x^n
		@param coefs: array list of coefficients. Its size does not have to
		be power of 2
		@param config: the config object
	*/ 	
	public Polynomial(ArrayList<FieldT> inp_coefs, Configuration config){
		//1. expand degree to 2^n
		int old_n = inp_coefs.size();
		if(old_n==0){Tools.panic("coefs has to contain at least one element!");}
		this.degree = MathUtils.lowestPowerOfTwo(old_n);
		ArrayList<FieldT> paddedArr = Utils.padArray(inp_coefs, this.degree);
		this.zero = inp_coefs.get(0).zero();
		this.config = config;

		//2. set up JavaPairRDD for co-efficients
		this.coefs = config.getSC().parallelizePairs(Utils.convertToPairs(paddedArr));
	}

	/** construct a polynomial instance by setting its coefs directly
	*/
	public Polynomial(int degree, JavaPairRDD<Long, FieldT> coefs, Configuration config, FieldT zero){
		//1. take data
		this.degree =degree;
		this.coefs= coefs;
		this.zero = zero;
		this.config = config;
	}

	/** construct a polynomial instance by setting its POINTS, the last
		parameter determine if need to convert coefs right now
	*/
	public Polynomial(int degree, JavaPairRDD<Long, FieldT> points, Configuration config, boolean bSetCoefs, FieldT zero){
		this.degree =degree;
		this.points= points;
		this.config = config;
		this.zero = zero;
		if(bSetCoefs){
			this.reset_coef_by_points();
		}
	}

	/** return coefs */
	public JavaPairRDD<Long,FieldT> getCoefs(){
		if(this.coefs==null){//assume points are there
			this.reset_coef_by_points();
		}
		return this.coefs;
	}

	/** Extend to the given newdegree. Basically it's to
		pad the coefs with extra zeros. 
		TODO: allow for capacity 2G.
	*/
	public void extendToDegree(int newdegree){
		int diff_size = newdegree - this.degree;
		ArrayList<FieldT> newpart = new ArrayList<FieldT>(
			Collections.nCopies(diff_size, zero));
		JavaPairRDD<Long,FieldT> newrdd= config.getSC().parallelizePairs(
			Tools.convertToPairsShifted(newpart, this.degree)
		);
		this.coefs = this.coefs.union(newrdd);
		this.degree = newdegree;
	}

	/** dump the co-efficients from the JavaPairRDD array.
		limit the items by n
	*/
	public void dump_coefs(int maxdegree){
		System.out.println(" ==== dump_coefs ====");
		System.out.println("Degree: " + this.degree);
		int max = maxdegree>this.degree? this.degree: maxdegree;
		this.dumpRDD(this.coefs, max);
	}

	/** get the proper row size for distributed FFT
	@param size - must be 2^k */
	public int getDistRowSize(int size){
		final int k = MathUtils.lowestPowerOfTwo((int)Math.sqrt(size));
        final int rows = size / k;
		return rows;
	}

	/** get the proper row size for distributed FFT
	@param size - must be 2^k */
	public int getDistColSize(int size){
		final int k = MathUtils.lowestPowerOfTwo((int)Math.sqrt(size));
		return k;
	}

	/** return the point representation. If it's not set, set it */
	public JavaPairRDD<Long,FieldT> getPoints(){
		if(points==null){//compute it
			long rows = this.getDistRowSize(this.degree);
			long cols= this.getDistColSize(this.degree);
			this.points = DistributedFFT.
				radix2FFT(this.coefs, rows, cols, zero);
		}
		return points;
	}

	/** reset the co-efficients by the points .*/
	public void reset_coef_by_points(){
		if(points==null){Tools.panic("points is null!");}
		int rows = this.getDistRowSize(this.degree);
		int cols= this.getDistColSize(this.degree);
		this.coefs= DistributedFFT.
				radix2InverseFFT(this.points, rows, cols, zero);
	}


	/** sum up two polynomials. Note: both input polynomials
		might be raised to a higher degree */
	public Polynomial add(Polynomial b){
		//1. line up degree
		int degree = this.degree>b.degree? this.degree: b.degree;
		if(this.degree<degree) {this.extendToDegree(degree);}
		if(b.degree<degree) {b.extendToDegree(degree);}
	
		//2. simply sum the coefs	
		//2. sum jdd
		JavaPairRDD<Long,FieldT> c1= this.getCoefs();
		JavaPairRDD<Long,FieldT> c2 = b.getCoefs();
		JavaPairRDD<Long,FieldT> c3 = binop(c1, c2, ADD);
		
		//3. create return
		Polynomial res = new Polynomial(degree, c3, this.config, this.zero);
		return res;
	}

	/** multiply two polynomials. Note: both input polynomials
		might be raised to a higher degree */
	public Polynomial mul(Polynomial b){
		//1. line up degree
		config.beginLog("ExtendDegree");
		int degree = this.degree>b.degree? this.degree: b.degree;
		degree *= 2;
		if(this.degree<degree) {this.extendToDegree(degree);}
		if(b.degree<degree) {b.extendToDegree(degree);}
		int count = (int) b.coefs.count();
		config.endLog("ExtendDegree");
	
		//2. mul 
		config.beginLog("MUL");
		JavaPairRDD<Long,FieldT> c1= this.getPoints();
		JavaPairRDD<Long,FieldT> c2 = b.getPoints();
		JavaPairRDD<Long,FieldT> c3 = binop(c1, c2, MUL);
		long ct = c1.count() + c2.count() + c3.count();
		config.endLog("MUL");
		
		//3. create return
		config.beginLog("PointsToCoeff");
		Polynomial res = new Polynomial(degree, c3, this.config, true, this.zero);
		long ct3 = res.getCoefs().count();
		config.endLog("PointsToCoeff");
		return res;
	}

	/** evaluate the polynomial at a given point */
	public FieldT eval(FieldT x){
		//int partitionSize = this.getDistRowSize(this.degree); 
		final int partitionSize = MathUtils.lowestPowerOfTwo((int) Math.sqrt(degree));

		config.beginLog("parallelEval");
		FieldT res = NaiveEvaluation.parallelEvaluatePolynomial(
			this.coefs, x, partitionSize);
		config.endLog("parallelEval");
		return res;
	}
	//--------------------------------
	//endregion PUBLIC Methods
	//--------------------------------

	//--------------------------------
	//region protected Methods
	//--------------------------------
	/** Sum/Mul up two rdd. Assumption: both are of 2^k size and both
		are fully populated with keys, and one value for each key.
		@param has to be ADD or MUL
	*/
	protected JavaPairRDD<Long,FieldT> binop(JavaPairRDD<Long,FieldT> a,
			JavaPairRDD<Long,FieldT> b, int op){
		JavaPairRDD<Long,FieldT> u2 = a.union(b);
        final Combiner<FieldT> combine = new Combiner<>();
		JavaPairRDD<Long,FieldT> retRDD= u2.mapToPair(element -> {
			return new Tuple2<>(element._1, new Tuple2<>(element._1, element._2));
		}).combineByKey(combine.createGroup,
			combine.mergeElement, combine.mergeCombiner).
			mapValues(partition->{//only 2 elements per group
				if(partition.size()!=2){Tools.panic("partition size is not 2!");}
				FieldT res =null;
				if(op==ADD){
					res = partition.get(0)._2.add(partition.get(1)._2);
				}else if(op==MUL){
					res = partition.get(0)._2.mul(partition.get(1)._2);
				}else{
					Tools.panic("Unsupported bin op: " + op);
				}
				return res;
			});
		return retRDD;
	} 

	/** dump entries from RDD */
	protected void dumpRDD(JavaPairRDD<Long,FieldT> rdd, int max){
		for(int i=0; i<max; i++){
			List<FieldT> list = rdd.lookup(Long.valueOf(i));
			if(list==null || list.size()==0){Tools.panic("no val for " + i);}
			FieldT val = list.get(0);
			System.out.println(i + ": " + val);
		}
	}
	//--------------------------------
	//endregion protected Methods
	//--------------------------------

}
