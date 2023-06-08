#!/bin/sh
RAYON_NUM_THREADS=4
RUST_BACKTRACE=1
mpirun --map-by node --quiet -mca btl self,tcp -mca btl_tcp_if_exclude br-7406b8232d20,docker0,lo,wlp61s0 -v --hostfile /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/acc/batchscripts/nodes.txt -np 4 /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/main/../acc/target/release/acc batch_prove /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/acc/batchscripts/nodes.txt /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/acc/batchscripts/jobs/job_14_10.txt /tmp2/batchprove /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/acc/batchscripts/results/ BLS12-381 /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/DATA/anti_virus_output/clamav_100 /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/acc/batchscripts/javamain.params.txt 4 /home/zkregex/Desktop/ProofCarryExec/Code/zkregex/DATA/anti_virus_input/clamav_100/sigs.dat skip_batch_preprocess=false skip_batch_gcd=false
