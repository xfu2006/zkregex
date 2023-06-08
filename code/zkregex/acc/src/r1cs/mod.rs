/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/25/2022
*/

/* ****************************************************************
	This module provides functions related to R1CS (Rank 1 Constraint
System). It provide R1CS (standard serial), distributed R1CS
using MPI, and functions that convert R1CS to QAP instance (see
groth16 for QAP data structures). The variable naming convention follows
the ones used in DIZK.
	Reference: 
	[1] Groth, "On the Size of Pairing-Based Non-interactive Arguments", https://eprint.iacr.org/2016/260.pdf
	[2] Wu, Zheng, Chiesa, Popa, Stoica, "DIZK: A Distributed Zero 
Knowledge Proof System",
	[3] DIZK source: https://github.com/scipr-lab/dizk
   **************************************************************** */
pub mod serial_r1cs;
pub mod dis_r1cs;
pub mod r1cs_tests;
