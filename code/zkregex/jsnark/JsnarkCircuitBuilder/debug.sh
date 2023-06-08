./start_sage_server.sh
# debug the circuit generation
#jdb -sourcepath "src" -classpath "bin:bcprov-jdk15on-159.jar:gson.jar" za_interface.ZaDataGen -Xmx

# debug the simple test
jdb -sourcepath "src" -classpath "bin:/usr/share/java/junit4.jar:bcprov-jdk15on-159.jar:gson.jar" org.junit.runner.JUnitCore za_interface.za.circs.tests.SimpleTest 

