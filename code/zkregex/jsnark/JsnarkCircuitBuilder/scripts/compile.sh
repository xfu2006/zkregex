# debug version
cp ../../nfa/ac/target/ac-1.0-SNAPSHOT.jar ./
cp ../../main/target/zkregex-1.0-SNAPSHOT.jar ./
cp *.jar target/
javac -g -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar:zkregex-1.0-SNAPSHOT.jar  $(find ./src/* | grep ".java$") 

# non-debug version
#javac  -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar:zkregex-1.0-SNAPSHOT.jar $(find ./src/* | grep ".java$") 

cd bin
jar cf jsnark.jar .
mv jsnark.jar ../target/
