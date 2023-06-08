#rm -fr run_dir/serialize/*
./start_sage_server.sh
java -Xmx4096m -cp bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar za_interface.ZaDataGen 

# zemoduler verifier
#java -Xmx4096m -cp bin:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar za_interface.ZaRegexCircRunner 1 0 4 ../../DATA/17a24 1122 Bls381

