/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   Spark Job Classes 
*	Author: Dr. CorrAuthor
*	Created: 05/01/2022
* *******************************************/
package cs.Employer.poly;
import java.util.ArrayList;
import java.io.Serializable;

/** parent class of FFTJob and MergeJob */
class Job<FieldT extends MontFieldElement<FieldT>> implements Serializable{
	public long id; //job id
	public long job_id;  //the job_id (very first ID)
	public ArrayList<FieldT> arr; //the list of co-efs or values
	protected FieldT fac;
	public Job(long job_id, long id, ArrayList<FieldT> arr, FieldT fac){
		this.id = id;
		this.job_id = job_id;
		this.arr = arr;
		this.fac = fac;
	}
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append("Job: job_id: " + Long.toHexString(job_id) + 
				", id: " + Long.toHexString(id));
		int limit = arr.size()<10? arr.size(): 10;
		return sb.toString() + arr_to_str("Arr", arr);
	}
	public String arr_to_str(String prefix, ArrayList<FieldT> arr){
		StringBuilder sb = new StringBuilder();
		sb.append(prefix + ": [");
		for(int i=0; i<arr.size(); i++){
			sb.append(arr.get(i).toString());
			String s_end = i==arr.size()-1? "]": ", ";
			sb.append(s_end);
		}
		return sb.toString();
	}

}
/** Internal job which models a task for distributed RecursiveFFT.
Forward computing FFT
*/
class FFTJob <FieldT extends MontFieldElement<FieldT>> extends Job<FieldT>{
	public FFTJob(long job_id, long id, ArrayList<FieldT> arr, FieldT fac){
		super(job_id, id, arr, fac);
	}
	/** return the children job, return the two children jobs */
	public ArrayList<FFTJob>  children(){
		int n = this.arr.size();
		ArrayList<FieldT> a0 = new ArrayList<>();
		ArrayList<FieldT> a1 = new ArrayList<>();
		for(int i=0; i<n/2; i++){
			a0.add(fac.zero());
			a1.add(fac.zero());
			a0.get(i).copyFrom(arr.get(i*2));
			a1.get(i).copyFrom(arr.get(i*2+1));
		}
		FFTJob j0 = new FFTJob(job_id, id<<1, a0, fac);
		FFTJob j1 = new FFTJob(job_id, (id<<1)+1, a1, fac);
		ArrayList<FFTJob> res = new ArrayList<>();
		res.add(j0);
		res.add(j1);
		return res;
	}
	/** fork children jobs until the size reached the desired_size */
	public void fork_to(int desired_size, ArrayList<FFTJob> result){
		if(this.arr.size()<=desired_size){
			result.add(this);
			return;
		}
		//recursion
		ArrayList<FFTJob> arrc = this.children();
		arrc.get(0).fork_to(desired_size, result);
		arrc.get(1).fork_to(desired_size, result);
	}
	/** process itself and produce a merge job */
	public MergeJob fft(){
		long t1 = System.currentTimeMillis();
		FFT fft = new FFT(fac);
		long t2 = System.currentTimeMillis();
		ArrayList<FieldT> arr = fft.serialRecursiveFFT(this.arr);	
		long id = this.id>>>1;
		int bit = (int) (this.id & 0x01L);
		MergeJob mj = new MergeJob(this.job_id, id, arr, bit, fac);
		long t3 = System.currentTimeMillis();
		System.out.println("FFTJob.fft(): create FFT(): " + 
			(t2-t1)+ "ms, cost: " + (t3-t1)+ "ms");
		return mj;
	}
}

/** represents a job to merge. There is ALWAYS a job
to merge with the SAME id, when id is 0, there is
no more to merge */
class MergeJob <FieldT extends MontFieldElement<FieldT>>  extends Job <FieldT>{
	int bit = 0; //represents if it's the left or right half
	public MergeJob(long job_id, long id, ArrayList<FieldT> arr, int bit, FieldT fac){
		super(job_id, id, arr, fac);
		this.bit = bit;
	}
	public String toString(){
		return super.toString() + ", bit: " + this.bit;
	}
	/** merge with the other job */
	public MergeJob merge(MergeJob other){
		long t1 = System.currentTimeMillis();
		assert(other.id==id && other.job_id==job_id && bit!=other.bit):
			"id or job_id not match";
		ArrayList<FieldT> y0 = bit==0? this.arr: other.arr;
		ArrayList<FieldT> y1 = bit==1? this.arr: other.arr;
		ArrayList<FieldT> y = new ArrayList<>();
		int n = this.arr.size()*2;
		for(int i=0; i<n; i++){
			y.add(fac.zero());
		}
	
		FieldT omega = fac.one();
		FieldT t = fac.zero();
		FieldT root = fac.rootOfUnity(n);
		for(int k=0; k<n/2; k++){
			y1.get(k).mulTo(omega, t);
			y0.get(k).subTo(t, y.get(k+n/2));
			y0.get(k).addTo(t, y.get(k));
			omega.mulWith(root);
		}
	
		MergeJob ret = new MergeJob(job_id, id>>>1, y, (int)(id & 0x01L), fac);	
		long t2 = System.currentTimeMillis();
		System.out.println("MergeJob cost: " + (t2-t1)+ "ms");
		return ret;
	}
	/** find a pair that are good to merge. Put the two result
		into res, and remove them from arr. 
		Assumption: should ALWAYS be able to find a pair,
		as long as arr.size() greater than 1
	*/
	public void find_pair(ArrayList<MergeJob> arr, ArrayList<MergeJob> res){
		if(arr.size()<=1) return;
		MergeJob job1=null;
		MergeJob job2=null;
		boolean bFound = false;
		for(int i=0; i<arr.size() && !bFound; i++){
			job1 = arr.get(i);
			for(int j=0; j<arr.size() && !bFound; j++){
				job2 = arr.get(j);
				if(job1.job_id==job2.job_id && job1.bit!=job2.bit &&
					job1.id==job2.id){
					bFound = true;
					break;
				}
			}
		}
		assert(bFound) : "bFound is false! arrSize is: " + arr.size();
		arr.remove(job1);
		arr.remove(job2);
		res.clear();
		res.add(job1);
		res.add(job2);
	}
}
