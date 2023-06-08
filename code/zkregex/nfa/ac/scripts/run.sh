#java -Xmx12g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App build_dfa ../../DATA/anti_virus_input/clamav_5 ../../DATA/anti_virus_output/clamav_5
#java -Xmx12g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App sample1
#java -Xmx12g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App sample2
# -- Generate simple clamav
#java -Xmx12g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App scan ../../DATA/anti_virus_input/clamav_5 /usr/bin  
# -- Generate FULL clamav data and scan /usr/bin for 100 files
java -Xmx30g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App scan ../../DATA/anti_virus_input/clamav_full /
#java -Xmx12g -cp target/ac-1.0-SNAPSHOT.jar cs.Employer.ac.App scan ../../DATA/anti_virus_input/clamav_100 /usr/sbin/grub-install
