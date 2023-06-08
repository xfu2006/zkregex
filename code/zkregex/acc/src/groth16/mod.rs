/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/18/2022
*/

/* ****************************************************************
	This module implements an extended Groth'16 system.
	The secret witness are divided into several segments called
"commited witness" to allow a 2-stage proof generation process
that combines an external Sigma-proof protocol with the zkSnark system
(see the zkRegex paper).
	The system is also expanded using openmpi to support parallel
proof generation. The core function of polynomial multiplication
uses the one introduced in DIZK.
	Reference: 
	[1] Groth, "On the Size of Pairing-Based Non-interactive Arguments", https://eprint.iacr.org/2016/260.pdf
	[2] Wu, Zheng, Chiesa, Popa, Stoica, "DIZK: A Distributed Zero 
Knowledge Proof System",
	[3] DIZK source: https://github.com/scipr-lab/dizk
   **************************************************************** */
pub mod new_dis_qap;
pub mod serial_qap;
pub mod serial_prove_key;
pub mod dis_prove_key;
pub mod serial_prover;
pub mod dis_prover;
pub mod common;
pub mod verifier;
pub mod groth16_test;
pub mod aggregate;

/*
pub mod serial_r1cs;
pub mod dis_r1cs;
pub mod r1cs_tests;
 */
