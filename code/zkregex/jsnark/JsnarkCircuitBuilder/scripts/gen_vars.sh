#rm -fr run_dir/serialize/*

# zemoduler verifier
java -Xmx4096m -cp bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar za_interface.ZaRegexCircRunner genr1cs 40 0 4 /tmp/batchprove/101 11223344 BLS12-381 16148

java -Xmx4096m -cp bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar za_interface.ZaRegexCircRunner genvars 40 0 4 /tmp/batchprove/101 11223344 BLS12-381 16148

python3 scripts/debug_vars.py
