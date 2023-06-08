/** Efficient Zero Knowledge Project
 	Zkreg's Version	of R1CSRelation object from DIZK
	Author: Dr. CorrAuthor and Author1
	Created: 06/09/2022
*/ 

package cs.Employer.dizk_driver;
//import algebra.fields.AbstractFieldElementExpanded;
import algebra.curves.barreto_naehrig.BNFields.*;
import relations.objects.*;
import scala.Tuple3;
import scala.Tuple2;
import relations.r1cs.R1CSRelation;
import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import algebra.fields.abstractfieldparameters.AbstractFpParameters;
import algebra.fields.Fp;
import java.util.List;
import java.util.ArrayList;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaPairRDD;
import relations.r1cs.R1CSRelationRDD;
import configuration.Configuration;

public class ZkrgxR1CSRelation<BNFrT extends BNFr<BNFrT>>{ 
	/** Protected Data Members.
		For curve settings */
	protected BNFrT fieldFactory;
	protected AbstractFpParameters parameters;
	protected Configuration config;
	
	/** Private Data Members.
		For dump() functionality */
	private R1CSRelation<BNFrT> r1cs;
	private Assignment<BNFrT> primary;
	private Assignment<BNFrT> auxiliary;

	private R1CSRelationRDD<BNFrT> r1csRDD;
	private JavaPairRDD<Long,BNFrT> fullAssignment; // primary and auxiliary combined

	/** constructor.
		create ZkrgxR1CSRelation object with fieldFactory and parameter settings */
	public ZkrgxR1CSRelation(
			BNFrT fieldFactory, 
			AbstractFpParameters parameters, 
			Configuration config){
		this.fieldFactory = fieldFactory;
		this.parameters = parameters;
		this.config = config; // can be null for serial version
	}

		/** parse given r1cs file to generate R1CS relation and assignments objects.
		@return Tuple3 of R1CSRelation, PrimaryInputs, AuxiliaryInputs */
	public Tuple3<R1CSRelation<BNFrT>, Assignment<BNFrT>, Assignment<BNFrT>> genR1CS(String fpath){
		try{
			BufferedReader r = new BufferedReader(new FileReader(fpath));
			
			// line 1 = field order
			String line = r.readLine();

			// line 2 = input size
			line = r.readLine();
			int _numInputs = parseTitle(line);
	
			// line 3 = aux input size
			line = r.readLine();
			int _numAuxiliary = parseTitle(line);

			// line 4 = num constraints
			line = r.readLine();
			int _numConstraints = parseTitle(line);

			// line 5 = "assignments:"
			r.readLine();

			// primary inputs
			int i = 0;
			line = r.readLine();
			Assignment<BNFrT> _primary = new Assignment<BNFrT>();
	 		while(i < _numInputs){
				BigInteger value = new BigInteger(line.split(" ")[1]);
				_primary.add(fieldFactory.construct(new Fp(value, parameters)));
				line = r.readLine();
				i++;
			}

			// auxiliary inputs
			Assignment<BNFrT> _auxiliary = new Assignment<BNFrT>();
			while(i < _numAuxiliary+_numInputs){
				BigInteger value = new BigInteger(line.split(" ")[1]);
				_auxiliary.add(fieldFactory.construct(new Fp(value, parameters)));
				line = r.readLine();
				i++;
			}
			// line = "constraints:"
			int num = 0; 
			R1CSConstraints<BNFrT> _constraints = new R1CSConstraints<>();
			LinearCombination<BNFrT> A = new LinearCombination<BNFrT>();
			LinearCombination<BNFrT> B = new LinearCombination<BNFrT>();
			LinearCombination<BNFrT> C = new LinearCombination<BNFrT>();

			// constraints
			line = r.readLine();
			while (line != null){
				String[] c = line.split(" ");
				int c_num = Integer.parseInt(c[0]);
				if (c_num != num){
					num++;
					_constraints.add(new R1CSConstraint<>(A,B,C));

					A = new LinearCombination<BNFrT>();
					B = new LinearCombination<BNFrT>();
					C = new LinearCombination<BNFrT>();
					
				}
			
				long idx = Long.parseLong(c[2]);
				BigInteger value = new BigInteger(c[3]);
				BNFrT term = fieldFactory.construct(new Fp(value,parameters));
				
				if (c[1].equals("A")){
					A.add(new LinearTerm<>(idx,term));
				}
				else if (c[1].equals("B")){
					B.add(new LinearTerm<>(idx,term));
				}
				else if (c[1].equals("C")){
					C.add(new LinearTerm<>(idx,term));
				}
				line = r.readLine();
			}

			// Add final combination
			_constraints.add(new R1CSConstraint<>(A,B,C));

			R1CSRelation<BNFrT> _relation = new R1CSRelation(_constraints, _numInputs, _numAuxiliary);
			primary = _primary;
			auxiliary = _auxiliary;	
			r1cs = _relation;

			return new Tuple3<>(_relation,_primary,_auxiliary);
		}
		catch(Exception e){
			System.out.println("ZkrgxR1CSRelation.genR1CS(): " + e.toString());
		}
		return null;
	}

	public Tuple3<R1CSRelationRDD<BNFrT>, Assignment<BNFrT>, JavaPairRDD<Long,BNFrT>> genR1CSRDD(String fpath){
		try{
			BufferedReader r = new BufferedReader(new FileReader(fpath));
			
			// line 1 = field order
			String line = r.readLine();

			// line 2 = input size
			line = r.readLine();
			int _numInputs = parseTitle(line);
	
			// line 3 = aux input size
			line = r.readLine();
			int _numAuxiliary = parseTitle(line);

			// line 4 = num constraints
			line = r.readLine();
			int _numConstraints = parseTitle(line);

			// line 5 = "assignments:"
			r.readLine();
			
			// initialize assignments
			ArrayList<Tuple2<Long, BNFrT>> _fullAssignmentList = new ArrayList<Tuple2<Long,BNFrT>>();
			Assignment<BNFrT> _primary = new Assignment<BNFrT>();

			// primary inputs
			int i = 0;
			line = r.readLine();
	 		while(i < _numInputs){
				BigInteger value = new BigInteger(line.split(" ")[1]);
				BNFrT element = fieldFactory.construct(new Fp(value, parameters));
				_fullAssignmentList.add(new Tuple2((long)i,element));
				_primary.add(element);
				line = r.readLine();
				i++;
			}

			// auxiliary inputs
			while(i < _numAuxiliary+_numInputs){
				BigInteger value = new BigInteger(line.split(" ")[1]);
				BNFrT element = fieldFactory.construct(new Fp(value, parameters));
				_fullAssignmentList.add(new Tuple2((long)i,element));
				line = r.readLine();
				i++;
			}
			// line = "constraints:"

			// initialize combinations as list
			ArrayList<Tuple2<Long, LinearTerm<BNFrT>>> aList = 
				new ArrayList<Tuple2<Long, LinearTerm<BNFrT>>>();
			ArrayList<Tuple2<Long, LinearTerm<BNFrT>>> bList = 
				new ArrayList<Tuple2<Long, LinearTerm<BNFrT>>>();
			ArrayList<Tuple2<Long, LinearTerm<BNFrT>>> cList = 
				new ArrayList<Tuple2<Long, LinearTerm<BNFrT>>>();

			// constraints
			int num = 0; 
			line = r.readLine();
			while (line != null){
				// analyze line
				String[] c = line.split(" ");
				//int c_num = Integer.parseInt(c[0]);
				long c_num = Long.parseLong(c[0]);
		
				long idx = Long.parseLong(c[2]);
				BigInteger value = new BigInteger(c[3]);
				BNFrT term = fieldFactory.construct(new Fp(value,parameters));
				//!------------------------------------------------------------
				//IMPORTANT - idx -1 should be treated as 0 (its val is const 1)
				//!------------------------------------------------------------
				if(idx==-1){ idx = 0;}

				// add term to proper combination
				if (c[1].equals("A")){
					aList.add(new Tuple2<Long, LinearTerm<BNFrT>>(c_num,
								new LinearTerm<>(idx,term)));
				}
				else if (c[1].equals("B")){
					bList.add(new Tuple2<Long, LinearTerm<BNFrT>>(c_num,
								new LinearTerm<>(idx,term)));
				}
				else if (c[1].equals("C")){
					cList.add(new Tuple2<Long, LinearTerm<BNFrT>>(c_num,
								new LinearTerm<>(idx,term)));
				}
				line = r.readLine();
			}
			// convert lists to JavaPairRDD 
			JavaPairRDD A = getCombinationFromList(aList);
			JavaPairRDD B = getCombinationFromList(bList);
			JavaPairRDD C = getCombinationFromList(cList);

			// Prepare return objects
			R1CSConstraintsRDD<BNFrT> _constraints = new R1CSConstraintsRDD(A,B,C,_numConstraints);
			R1CSRelationRDD<BNFrT> _r1csRDD = 
				new R1CSRelationRDD(_constraints, _numInputs, _numAuxiliary);

			JavaPairRDD _fullAssignment = getFullAssignmentFromList(_fullAssignmentList);

			// update member objects
			primary = _primary;
			
			fullAssignment = _fullAssignment;
			r1csRDD = _r1csRDD;

			return new Tuple3<>(_r1csRDD,_primary,_fullAssignment);
		}
		catch(Exception e){
			System.out.println("ZkrgxR1CSRelation.genR1CSRDD(): " + e.toString());
		}
		return null;
	}

	/** dump the contents in JSnark format */
	public void dump(){
		int numInputs = r1cs.numInputs();
		int numVariables = r1cs.numVariables();
		int numAuxiliary = numVariables - numInputs;
		int numConstraints = r1cs.numConstraints();

		System.out.println("primary_input_size: " + numInputs);
		System.out.println("aux_input_size: " + numAuxiliary);
		System.out.println("num_constraints: " + numConstraints);

		System.out.println("assignments:" );
		printAssignment(primary, 0);
		if (auxiliary!=null){printAssignment(auxiliary, numInputs);}
	
		System.out.println("constraints:" );

		// jsnark style
		for (int i = 0; i < numConstraints; i++){
			printCombinations(r1cs.constraints(i), i);
		}
	}

	/** dump contents to mirror RDD */
	public void dumpSerial(){
		int numInputs = r1cs.numInputs();
		int numVariables = r1cs.numVariables();
		int numAuxiliary = numVariables - numInputs;
		int numConstraints = r1cs.numConstraints();

		System.out.println("input_size: " + (numInputs + numAuxiliary));
		System.out.println("primary_input_size: " + numInputs);
		System.out.println("aux_input_size: " + numAuxiliary);
		System.out.println("num_constraints: " + numConstraints);

		System.out.println("assignments:" );
		printAssignment(primary, 0);
		if (auxiliary!=null){printAssignment(auxiliary, numInputs);}
	
		System.out.println("constraints:" );
		
		// RDD style
		for (int i = 0; i < numConstraints; i++){
			LinearCombination A = r1cs.constraints(i).A();
			printTerms(A, "A", i);
		}
		for (int i = 0; i < numConstraints; i++){
			LinearCombination B = r1cs.constraints(i).B();
			printTerms(B, "B", i);
		}
		for (int i = 0; i < numConstraints; i++){
			LinearCombination C = r1cs.constraints(i).C();
			printTerms(C, "C", i);
		}
	}

	/** dump the RDD contents in nice format */
	public void dumpRDD(){
		int numInputs = r1csRDD.numInputs();
		long numVariables = r1csRDD.numVariables();
		long numAuxiliary = numVariables-(long)numInputs;
		long numConstraints = r1csRDD.numConstraints();

		System.out.println("input_size: " + (numInputs + numAuxiliary));
		System.out.println("primary_input_size: " + numInputs);
		System.out.println("aux_input_size: " + numAuxiliary);
		System.out.println("num_constraints: " + numConstraints);

		System.out.println("assignments:" );

		fullAssignment.foreach(data -> {
			System.out.println(data._1() + " " + data._2().toBigInteger().toString());
		});

		System.out.println("constraints:");

		R1CSConstraintsRDD<BNFrT> c = r1csRDD.constraints();

		JavaPairRDD<Long, LinearTerm<BNFrT>> A = c.A();
		JavaPairRDD<Long, LinearTerm<BNFrT>> B = c.B();
		JavaPairRDD<Long, LinearTerm<BNFrT>> C = c.C();

		A.foreach(data -> {
			BNFrT value = data._2().value();
			long index = data._2().index();
			System.out.println(data._1() + " A " + index + " " + value.toBigInteger().toString());
		});
		B.foreach(data -> {
			BNFrT value = data._2().value();
			long index = data._2().index();
			System.out.println(data._1() + " B " + index + " " + value.toBigInteger().toString());
		});
		C.foreach(data -> {
			BNFrT value = data._2().value();
			long index = data._2().index();
			System.out.println(data._1() + " C " + index + " " + value.toBigInteger().toString());
		});
	}

	// print each combination for a given constraint
	private void printCombinations(R1CSConstraint c, int c_num){
		LinearCombination A = c.A();
		LinearCombination B = c.B();
		LinearCombination C = c.C();
		printTerms(A,"A",c_num);
		printTerms(B,"B",c_num);
		printTerms(C,"C",c_num);
	}

	// print all serial terms given a combination
	private void printTerms(LinearCombination l, String title, int c_num){
		ArrayList<LinearTerm<BNFrT>> terms = l.terms();
		for (LinearTerm<BNFrT> t : terms){
			BNFrT term = t.value();
			printTerm((long)c_num, title, t.index(), term);
		}
	}

	// print individual term
	private void printTerm(long c_num, String title, long index, BNFrT term){
			System.out.println(c_num + " " + title + " " + index + " " + term.toBigInteger().toString());
	}

	// print an Assignment object
	private void printAssignment(Assignment<BNFrT> a, int start){
		ArrayList<BNFrT> elements = a.elements();
		for (int i = 0; i < a.size(); i++){
			BNFrT e = a.get(i);
			System.out.println(i+start + " " + e.toBigInteger().toString());
		}
	}

	// for regex parsing titles: e.g. line = "aux_input_size: 1"
	private static int parseTitle(String line){
		return Integer.parseInt(line.split(": ")[1]);
	}

	// convert ArrayList to JavaPairRDD; equivalent to serial LinearCombination type
	private JavaPairRDD getCombinationFromList(ArrayList<Tuple2<Long, LinearTerm<BNFrT>>> list){
		JavaRDD rdd = config.sparkContext().parallelize(list);
		return JavaPairRDD.fromJavaRDD(rdd);
	}

	private JavaPairRDD getFullAssignmentFromList(ArrayList<Tuple2<Long,BNFrT>> list){
		JavaRDD rdd = config.sparkContext().parallelize(list);
		return JavaPairRDD.fromJavaRDD(rdd);
	}
}
