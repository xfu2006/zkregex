/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Fast Fourier Transform
*	Author: Dr. CorrAuthor
*	Created: 05/01/2022
* *******************************************/
package cs.Employer.poly;


import algebra.fields.AbstractFieldElementExpanded;
import common.Combiner;
import common.MathUtils;
import common.Utils;
import configuration.Configuration;
import org.apache.spark.api.java.JavaPairRDD;
import scala.Tuple2;
import cs.Employer.zkregex.NanoTimer;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.broadcast.Broadcast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.io.Serializable;

/* Helper class to avoid serialization issues in SPARK */
class FFTHelper<FieldT extends MontFieldElement<FieldT>> implements Serializable{
	public ArrayList<FieldT> serialRecursiveFFT(
		final ArrayList<FieldT> input){
		FFT fft = new FFT(input.get(0).zero());
		return fft.serialRecursiveFFT(input);
	}
}
/* This class is mainly the adaptation of DIZK's 
algebra/fft classes. 
   The differences are: (1) we enforce the use of MontFieldElement so that
we can take advantage of the Montgomery reduction based arithmetic for
fast finite field operation; (2) we use the MUTABLE object operations so 
that most dynamic object creation cost can be avoided.
NOTE: this class is NOT threadsafe, as some common scratch pad field elements
are used during operation. At any time, the object should be OWNED and USED
by just ONE thread. 
*/
public class FFT <FieldT extends MontFieldElement<FieldT>> implements Serializable{
	// ------------------------------------------------------
	// region DATA MEMBERS
	// ------------------------------------------------------
	/** factory object of fieldT */
	protected FieldT fac = null;
	/** CONSTANT 1 */
	protected final FieldT ONE;
	/** scratch pad variable.*/
	protected FieldT w = null;
	/** scratch pad variable.*/
	protected FieldT t = null;
	/** scratch pad variable.*/
	protected FieldT t2 = null;
	/** omega's roots of unity for 0 ... */
	protected ArrayList<FieldT> arrOmega;
	/** scratch pad for w in serialFT */
	protected ArrayList<FieldT> arrw = new ArrayList<>();
	/** scratch pad for w in serialFT */
	public static final int DEFAULT_ARRW_SIZE = 1024;
	// ------------------------------------------------------
	// end region DATA MEMBERS
	// ------------------------------------------------------

	// ------------------------------------------------------
	// region public operations
	// ------------------------------------------------------

	/** Constructor.
	@param t: pass an object of fieldT as factory object 
	*/
	public FFT(FieldT inp){
		this.fac = inp;
		this.w = inp.zero();
		this.t = inp.zero();
		this.t2 = inp.zero();
		this.ONE= inp.one();
		this.setupOmegas();
	}

	/** get the omega for order. order has to be 2^k. where k<=63 (good
		enough for most applications)  */
	public FieldT getOmega(int order){
		final int logn = MathUtils.log2(order);
		return arrOmega.get(logn);
	}

	/**
	 * Compute the radix-2 FFT of the vector a over the set S={omega^{0},...,omega^{m-1}}. Result is DIRECTLY APPLIED TO MODIFY each element in the
input array list. Adapted from DIZK's FFTAuxiliary.serialRadix2FFT 
	 */
	public void serialRadix2FFT(
			final ArrayList<FieldT> input,
			final FieldT omega) {
		final int n = input.size();
		//final int n = input.length;
		final int logn = MathUtils.log2(n);
		if (n == 1) { return; }
		assert (n == (1 << logn)) : "input n is not 2^k!";
		this.setupArrW(n);

		/* swapping in place (from Storer's book) */
		for (int k = 0; k < n; ++k) {
			final int rk = MathUtils.bitreverse(k, logn);
			if (k < rk) {
				Collections.swap(input, k, rk);
				//FieldT tmp = input[k];
				//input[k] = input[rk];
				//input[rk] = tmp;
			}
		}

		int m = 1; // invariant: m = 2^{s-1}

		arrw.set(0, ONE);
		for (int s = 1; s <= logn; ++s) {
			// w_m is 2^s-th root of unity now
			final FieldT w_m = omega.pow(n / (2 * m));
			this.setupArrW(m);
			for(int j=1; j<=m; j++){
				arrw.get(j-1).mulTo(w_m, arrw.get(j));
			}

			for (int k = 0; k < n; k += 2 * m) {
				w = arrw.get(0);
				for (int j = 0; j < m; ++j) {
					//1. final FieldT t = w.mul(input.get(k + j + m));
					FieldT t_kjm = input.get(k+j+m);
					FieldT t_kj = input.get(k+j);
					//w.mulTo(t_kjm, t);
					arrw.get(j).mulTo(t_kjm, t);

					//2. input.set(k + j + m, input.get(k + j).sub(t));
					t_kj.subTo(t, t_kjm);

					//3. input.set(k + j, input.get(k + j).add(t));
					t_kj.addWith(t);
			
					//4. w = w.mul(w_m);
					//w = arrw.get(j+1);
				}
			}
			m *= 2;
		}
	}

	/** Classical recursive implementation, assumption input size
		is 2^k .
		NOTE: input will be modified and returned
	*/
	public ArrayList<FieldT> serialRecursiveFFT(
		final ArrayList<FieldT> input){
		final int n = input.size();
		final int logn = MathUtils.log2(n);
		assert (n == (1 << logn)) : "input n is not 2^k!";

		//1. base case
		if (n == 1) { return input; }

		//2. recursion
		ArrayList<FieldT> a0 = new ArrayList<>();
		ArrayList<FieldT> a1 = new ArrayList<>();
		for(int i=0; i<n/2; i++){
			//a0.add(input.get(i*2)); -> as it's mutable, make copy first
			//a1.add(input.get(i*2+1));
			a0.add(this.fac.zero());
			a1.add(this.fac.zero());
			a0.get(i).copyFrom(input.get(i*2));
			a1.get(i).copyFrom(input.get(i*2+1));
		}
		ArrayList<FieldT> y0 = serialRecursiveFFT(a0);
		ArrayList<FieldT> y1 = serialRecursiveFFT(a1);
		ArrayList<FieldT> y = input;

		FieldT omega = this.fac.one();
		FieldT t = this.fac.zero();
		FieldT root = this.getOmega(n);
		for(int k=0; k<n/2; k++){
			y1.get(k).mulTo(omega, t);
			y0.get(k).subTo(t, y.get(k+n/2));
			y0.get(k).addTo(t, y.get(k));
			omega.mulWith(root);
		}
		return y;
	}
	/** Based on the classical recursive implementation. "Serial Version"
	of its distributed version. Tasks modeled using Job objects.
	assumption input size is 2^k .
		NOTE: input will be modified and returned
	*/
	public ArrayList<FieldT> serialRecursiveJobFFT(
		final ArrayList<FieldT> input,
		Configuration cfg){
		final int n = input.size();
		final int logn = MathUtils.log2(n);
		assert (n == (1 << logn)) : "input n is not 2^k";

		//1. base case
		int BAR_DISTRIBUTED = 3; //lower than this serial is better
		if (n == 1) { return input; }
		if (logn<=BAR_DISTRIBUTED) { return serialRecursiveFFT(input);}
		int partitions = (1<<(MathUtils.log2(cfg.numPartitions())));

		//2. build up the jobs 
		FFTJob init_job = new FFTJob(1L, 0L, input, fac);
		ArrayList<FFTJob> jobs = new ArrayList<>();
		init_job.fork_to(n/partitions, jobs);
		int nrounds = MathUtils.log2(partitions);

		//3. parallel execute all jobs
		ArrayList<MergeJob> merge_jobs= new ArrayList<>();
		for(int i=0; i<jobs.size(); i++){
			merge_jobs.add(jobs.get(i).fft());
		}

		//4. merge the jobs
		MergeJob mhandle = new MergeJob(0, 0, new ArrayList<FieldT>(), 0, fac);
		ArrayList<MergeJob> pair = new ArrayList<>();
		while(merge_jobs.size()>1){
			mhandle.find_pair(merge_jobs, pair);
			MergeJob res = pair.get(0).merge(pair.get(1));
			merge_jobs.add(res);
		}
		MergeJob final_res = merge_jobs.get(0);
		ArrayList<FieldT> y2 = final_res.arr;
		return y2;
	}


	/** Based on the classical recursive implementation, assumption input size
		is 2^k .
		NOTE: input will be modified and returned
	*/
	public ArrayList<FieldT> distributedRecursiveJobFFT(
		final ArrayList<FieldT> input,
		Configuration cfg){
		final int n = input.size();
		final int logn = MathUtils.log2(n);
		assert (n == (1 << logn)): "input n is not 2^k";

		//1. base case
		int BAR_DISTRIBUTED = 3; //lower than this serial is better
		if (n == 1) { return input; }
		if (logn<=BAR_DISTRIBUTED) { return serialRecursiveFFT(input);}
		int partitions = (1<<(MathUtils.log2(cfg.numPartitions())));

		//2. build up the jobs 
		FFTJob init_job = new FFTJob(1L, 0L, input, fac);
		ArrayList<FFTJob> jobs = new ArrayList<>();
		init_job.fork_to(n/partitions, jobs);
		JavaRDD<FFTJob> rdd_jobs = cfg.getSC().parallelize(jobs);
		int nrounds = MathUtils.log2(partitions);

		//3. parallel execute all jobs
		JavaPairRDD<Long, MergeJob> mg_jobs = rdd_jobs.mapToPair(x ->
			{
				MergeJob mj = x.fft();
				return new Tuple2<>(mj.id, mj);
			}
		);

		//4. merge the jobs
		for(int i=0; i<nrounds; i++){
			mg_jobs = mg_jobs.reduceByKey((c1, c2) -> c1.merge(c2)).
				mapToPair(x -> {
					final MergeJob c3 = x._2;
					return new Tuple2<>(c3.id, c3);
				});
		}

		MergeJob mj_final = mg_jobs.first()._2;
		return mj_final.arr;	

	}

	/** Convert the input to RDD.
		If length not power of 2, pad it to 0 at the end
	*/
	public JavaPairRDD<Long,FieldT> arr_to_rdd(
		ArrayList<FieldT> input, Configuration cfg){ 
		int n = input.size();
		final int logn = MathUtils.log2(n);
		n = (1 << logn);
		input = Utils.padArray(input, n);
		JavaPairRDD<Long,FieldT> res= cfg.getSC().parallelizePairs(Utils.convertToPairs(input));
		return res;
	}
	/** CAUTION: can't be applied to too large size 
		rebuild the logical data 
	*/
	public ArrayList<FieldT> rdd_to_arr(
		JavaPairRDD<Long,FieldT> input,
			Configuration cfg){
		List<Tuple2<Long,FieldT>> al = input.collect();
		int n = al.size();
		ArrayList<FieldT> res = new ArrayList<>(Collections.nCopies(n, fac)); 
		for(Tuple2<Long,FieldT> t: al){
			int id = t._1.intValue();
			FieldT f = t._2;
			res.set(id, f);
			
		}
		return res;
	}


	/** VERSION USED for junit testing. For production version,
		call distributedDizkFFT which directly works on JavaPairRDD
	*/
	public ArrayList<FieldT> distributedDizkFFT_wrapper(
		final ArrayList<FieldT> input,
		Configuration cfg){
		final int n = input.size();
		final int logn = MathUtils.log2(n);
		assert (n == (1 << logn)): "Input length has to be 2^k";

		JavaPairRDD<Long,FieldT> rdd_input = arr_to_rdd(input, cfg);
		JavaPairRDD<Long,FieldT> rdd = distributedDizkFFT(n, rdd_input, cfg);
		ArrayList<FieldT> res = rdd_to_arr(rdd, cfg);
		return res;
	}

	/** FFT processing using DIZK's row/col algorithm.
		This is adapted from DIZK's FFTAuxiliar.java code with
		slight change.
	*/
	public JavaPairRDD<Long, FieldT> distributedDizkFFT(
		int n, 
		final JavaPairRDD<Long, FieldT> input,
		Configuration cfg){
		//1. base case
		int BAR = 512;
		if(n<=BAR){//just do serial one - faster
			ArrayList<FieldT> alInput = rdd_to_arr(input, cfg);
			ArrayList<FieldT> alOut = serialRecursiveFFT(alInput);
			return arr_to_rdd(alOut, cfg);
		}

		//2. determine rows and columns
		assert (MathUtils.isPowerOfTwo(n)): "input size is not 2^k!";
		int k = MathUtils.log2(n);
		int rows = 1<<(k/2);
		int columns = n/rows;
		int size = rows*columns;
        final Combiner<FieldT> combine = new Combiner<>();
        final FieldT omegaShift = fac.rootOfUnity(size);
		Broadcast<FFT> bgfft = cfg.getSC().broadcast(this);

		//3. Forward FFT, do actually columns
		final JavaPairRDD<Long, FieldT> columnGroups = input.
			mapToPair(element->{
			final long group = element._1 % rows;
			final long index = element._1 / rows;
	
			return new Tuple2<>(group, new Tuple2<>(index, element._2));
		}).combineByKey(combine.createGroup, 
			combine.mergeElement, combine.mergeCombiner).mapValues(
			partition -> {
				//long t1 = System.currentTimeMillis();
				ArrayList<FieldT> groupArray = 
					Utils.convertFromPairs(partition, (int) columns);
	
				//if (inverse) {
				// columnDomain.radix2InverseFFT(groupArray);
				//} else {
				// columnDomain.radix2FFT(groupArray);
				//}
				//FFTHelper helper = new FFTHelper();
				FFT<FieldT> fft= bgfft.value();
				groupArray = fft.serialRecursiveFFT(groupArray);
				//long t2 = System.currentTimeMillis();
				//System.out.println("STEP 1: " + (t2-t1) + "ms");
				return groupArray;
			
		 	}).flatMapToPair(element -> {
				// bit shift
				//long t1 = System.currentTimeMillis();
				final long index = element._1;
				ArrayList<Tuple2<Long, FieldT>> combinedNumbers = 
					new ArrayList<>();
				final FieldT nthRoot = omegaShift.pow(0);
				final FieldT update = omegaShift.pow(index);
		 		for(int i = 0; i < columns; i++) {
			 		//final FieldT nthRoot = omegaShift.pow(index * i);
						//			 inverse ? omegaShift.pow(index * i).inverse() : omegaShift.pow(index * i);
			 		combinedNumbers.add(new Tuple2<>(i * rows + index, 
						nthRoot.mul(element._2.get(i))));
					nthRoot.mulWith(update);
				 }
				//long t2 = System.currentTimeMillis();
				//System.out.println("STEP 2: " + (t2-t1) + "ms");
				 return combinedNumbers.iterator();
			 });

		 //4. Forward FFT, Reducer 
		 return columnGroups.mapToPair(element -> {
			 final long group = element._1 / rows;
			 final long index = element._1 % rows;
			 return new Tuple2<>(group, new Tuple2<>(index, element._2));
		 }).combineByKey(combine.createGroup, 
			combine.mergeElement, combine.mergeCombiner)
		 	.mapValues(partition -> {
				//long t1 = System.currentTimeMillis();
			 	ArrayList<FieldT> groupArray = 
					Utils.convertFromPairs(partition, (int) rows);
 
			 	//if (inverse) {
				 //	rowDomain.radix2InverseFFT(groupArray);
			 	//} else {
				 //	rowDomain.radix2FFT(groupArray);
			 	//}
				//FFTHelper helper = new FFTHelper();
				FFT<FieldT> fft= bgfft.value();
				groupArray = fft.serialRecursiveFFT(groupArray);
				//long t2 = System.currentTimeMillis();
				//System.out.println("STEP 3: " + (t2-t1) + "ms");
			 	return groupArray;
		 	}).flatMapToPair(element -> {
				//long t1 = System.currentTimeMillis();
			 	final long index = element._1;
			 	ArrayList<Tuple2<Long, FieldT>> outputs = new ArrayList<>();
			 	for (int i = 0; i < rows; i++) {
				 outputs.add(new Tuple2<>(i * columns + index, 
					element._2.get(i)));
			 	}
				//long t2 = System.currentTimeMillis();
				//System.out.println("STEP 4: " + (t2-t1) + "ms");
			 	return outputs.iterator();
		 	});
	}

	/**
	 * A distributed version of serialRadix2FFT.
	 */
//	 static <FieldT extends AbstractFieldElementExpanded<FieldT>> JavaPairRDD<Long, FieldT>
//	 distributedRadix2FFT(
//			 final JavaPairRDD<Long, FieldT> input,
//			 final long rows,
//			 final long columns,
//			 final boolean inverse,
//			 final FieldT fac) {
//		 /* Initialization */
//		 final long size = rows * columns;
//		 final FieldT omegaShift = fac.rootOfUnity(size);
//		 final Combiner<FieldT> combine = new Combiner<>();
//		 final SerialFFT<FieldT> rowDomain = new SerialFFT<>(rows, fac);
//		 final SerialFFT<FieldT> columnDomain = new SerialFFT<>(columns, fac);
// 
//	 }
// 
//	 /**
//	  * Translate the vector input to a coset defined by g. Result is stored in ArrayList input.
//	  */
//	 static <FieldT extends AbstractFieldElementExpanded<FieldT>> void multiplyByCoset(
//			 final List<FieldT> input,
//			 final FieldT g) {
//		 FieldT coset = g;
//		 for (int i = 1; i < input.size(); ++i) {
//			 input.set(i, input.get(i).mul(coset));
//			 coset = coset.mul(g);
//		 }
//	 }
// 
//	 /**
//	  * A distributed version of multiplyByCoset.
//	  */
//	 static <FieldT extends AbstractFieldElementExpanded<FieldT>> JavaPairRDD<Long, FieldT>
//	 distributedMultiplyByCoset(
//			 final JavaPairRDD<Long, FieldT> input,
//			 final FieldT g) {
// 
//		 return input.mapToPair(term -> new Tuple2<>(term._1, term._2.mul(g.pow(term._1))));
//	 }
	// ------------------------------------------------------
	// end region public operations
	// ------------------------------------------------------

	// ------------------------------------------------------
	// region protected operations
	// ------------------------------------------------------
	/** set up the root of units */
	protected void setupOmegas(){
		this.arrOmega = new ArrayList<FieldT>();
		for(int i=0; i<63; i++){
			this.arrOmega.add(this.fac.rootOfUnity(1L<<i));
		}
	}
	protected void setupArrW(int size){
		if(this.arrw.size()<size){
			this.arrw = new ArrayList<>(Collections.nCopies(size, fac));	
			for(int i=0; i<size; i++){
				this.arrw.set(i, fac.zero());
			}
		}
	}
	// ------------------------------------------------------
	// end region protected operations
	// ------------------------------------------------------

}
