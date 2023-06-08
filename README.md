Quick Walk-Through of Zkregex Data and Code

1. Data
	[a] Fig7_DistributedSystemPerfData 
		-> Data related to Figure 7 
		(Distributed System Performance, FFT, Div, Groth16 etc)
		-----------------------------------------------
		Run run.sh to generate the eps figure.
		raw_data -> 2d table of data for gnuplots
		run_dumps -> the zkregex run dumps that generates raw_data
		template_scripts -> a python file that processes run_dumps to
			generate raw_data
		-----------------------------------------------
	[b] elf_list.txt: list of all ELF (object & exec) files in CentOS 7.1
		Each file record starts with "FILEDUMP"    
	[c] REPORT_ALL.txt: summary report of zk-proof generation for all ELFs
	[d] ZkProof_Logs: detailed report (time breakdown) and all zk-proofs
		Zkproofs are grouped in batches, e.g., "job_15_10" (file size
			2^15 and depth bound 10). 
	[e] AggregateLog: the generation log of aggregated proof, using
		inner pairing product

2. Code
	Major Components:
	* Jsnark: instrumented JSnark. arithmetic circuits in: jsnark/JsnarkCircuitBuilder/src/za_interface/za/circs/zkreg/  (other folders in za/circs include
		implementation of MiMC and Poseidon hash).
	* nfa/ac: implementation of the Aho-Corasick automata. Its data folder
		contains the ClamAV hex signature set.
	* main: java module for serialization and paper data collection
		its config folder sets the network architecture of HPC cluster.
	* acc: Rust module of the main system
		[a] poly - distributed polynomial operations (FFT, mul, div, gcd etc.)
		[b] groth16 - serial and distributed groth16 system
		[c] zkregex - main zkregex system
				[c.1] batch_prover.rs - main prover
				[c.2] aggregate.rs - aggregation using inner pairing product
		[d] proto - Sigma protocols
				[d.1] zk_kzg_v2.rs - univariate zk-VPD
				[d.2] zk_subset_v3.rs - zk-subset protocol
				[d.3] zk_conn.rs - zk-protocol for connecting chunks of 
					big files (split into 1MB chunks)

 

