#rm -fr run_dir/serialize/*
# --- JAR FILES after the first two copied from main...zkregex
./start_sage_server.sh 
java -Xmx4096m -cp bin:/usr/share/java/junit4.jar:bcprov-jdk15on-159.jar:gson.jar:../../main/target/zkregex-1.0-SNAPSHOT.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-core_2.10/2.2.2/spark-core_2.10-2.2.2.jar:/home/zkregex/.m2/repository/org/apache/avro/avro/1.7.7/avro-1.7.7.jar:/home/zkregex/.m2/repository/org/codehaus/jackson/jackson-core-asl/1.9.13/jackson-core-asl-1.9.13.jar:/home/zkregex/.m2/repository/org/codehaus/jackson/jackson-mapper-asl/1.9.13/jackson-mapper-asl-1.9.13.jar:/home/zkregex/.m2/repository/com/thoughtworks/paranamer/paranamer/2.3/paranamer-2.3.jar:/home/zkregex/.m2/repository/org/apache/commons/commons-compress/1.4.1/commons-compress-1.4.1.jar:/home/zkregex/.m2/repository/org/tukaani/xz/1.0/xz-1.0.jar:/home/zkregex/.m2/repository/org/apache/avro/avro-mapred/1.7.7/avro-mapred-1.7.7-hadoop2.jar:/home/zkregex/.m2/repository/org/apache/avro/avro-ipc/1.7.7/avro-ipc-1.7.7.jar:/home/zkregex/.m2/repository/org/apache/avro/avro-ipc/1.7.7/avro-ipc-1.7.7-tests.jar:/home/zkregex/.m2/repository/com/twitter/chill_2.10/0.8.0/chill_2.10-0.8.0.jar:/home/zkregex/.m2/repository/com/esotericsoftware/kryo-shaded/3.0.3/kryo-shaded-3.0.3.jar:/home/zkregex/.m2/repository/com/esotericsoftware/minlog/1.3.0/minlog-1.3.0.jar:/home/zkregex/.m2/repository/org/objenesis/objenesis/2.1/objenesis-2.1.jar:/home/zkregex/.m2/repository/com/twitter/chill-java/0.8.0/chill-java-0.8.0.jar:/home/zkregex/.m2/repository/org/apache/xbean/xbean-asm5-shaded/4.4/xbean-asm5-shaded-4.4.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-client/2.6.5/hadoop-client-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-common/2.6.5/hadoop-common-2.6.5.jar:/home/zkregex/.m2/repository/commons-cli/commons-cli/1.2/commons-cli-1.2.jar:/home/zkregex/.m2/repository/xmlenc/xmlenc/0.52/xmlenc-0.52.jar:/home/zkregex/.m2/repository/commons-httpclient/commons-httpclient/3.1/commons-httpclient-3.1.jar:/home/zkregex/.m2/repository/commons-io/commons-io/2.4/commons-io-2.4.jar:/home/zkregex/.m2/repository/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar:/home/zkregex/.m2/repository/commons-lang/commons-lang/2.6/commons-lang-2.6.jar:/home/zkregex/.m2/repository/commons-configuration/commons-configuration/1.6/commons-configuration-1.6.jar:/home/zkregex/.m2/repository/commons-digester/commons-digester/1.8/commons-digester-1.8.jar:/home/zkregex/.m2/repository/commons-beanutils/commons-beanutils/1.7.0/commons-beanutils-1.7.0.jar:/home/zkregex/.m2/repository/commons-beanutils/commons-beanutils-core/1.8.0/commons-beanutils-core-1.8.0.jar:/home/zkregex/.m2/repository/com/google/protobuf/protobuf-java/2.5.0/protobuf-java-2.5.0.jar:/home/zkregex/.m2/repository/com/google/code/gson/gson/2.2.4/gson-2.2.4.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-auth/2.6.5/hadoop-auth-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/directory/server/apacheds-kerberos-codec/2.0.0-M15/apacheds-kerberos-codec-2.0.0-M15.jar:/home/zkregex/.m2/repository/org/apache/directory/server/apacheds-i18n/2.0.0-M15/apacheds-i18n-2.0.0-M15.jar:/home/zkregex/.m2/repository/org/apache/directory/api/api-asn1-api/1.0.0-M20/api-asn1-api-1.0.0-M20.jar:/home/zkregex/.m2/repository/org/apache/directory/api/api-util/1.0.0-M20/api-util-1.0.0-M20.jar:/home/zkregex/.m2/repository/org/apache/curator/curator-client/2.6.0/curator-client-2.6.0.jar:/home/zkregex/.m2/repository/org/htrace/htrace-core/3.0.4/htrace-core-3.0.4.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-hdfs/2.6.5/hadoop-hdfs-2.6.5.jar:/home/zkregex/.m2/repository/org/mortbay/jetty/jetty-util/6.1.26/jetty-util-6.1.26.jar:/home/zkregex/.m2/repository/xerces/xercesImpl/2.9.1/xercesImpl-2.9.1.jar:/home/zkregex/.m2/repository/xml-apis/xml-apis/1.3.04/xml-apis-1.3.04.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-mapreduce-client-app/2.6.5/hadoop-mapreduce-client-app-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-mapreduce-client-common/2.6.5/hadoop-mapreduce-client-common-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-yarn-client/2.6.5/hadoop-yarn-client-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-yarn-server-common/2.6.5/hadoop-yarn-server-common-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-mapreduce-client-shuffle/2.6.5/hadoop-mapreduce-client-shuffle-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-yarn-api/2.6.5/hadoop-yarn-api-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-mapreduce-client-core/2.6.5/hadoop-mapreduce-client-core-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-yarn-common/2.6.5/hadoop-yarn-common-2.6.5.jar:/home/zkregex/.m2/repository/javax/xml/bind/jaxb-api/2.2.2/jaxb-api-2.2.2.jar:/home/zkregex/.m2/repository/javax/xml/stream/stax-api/1.0-2/stax-api-1.0-2.jar:/home/zkregex/.m2/repository/org/codehaus/jackson/jackson-jaxrs/1.9.13/jackson-jaxrs-1.9.13.jar:/home/zkregex/.m2/repository/org/codehaus/jackson/jackson-xc/1.9.13/jackson-xc-1.9.13.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-mapreduce-client-jobclient/2.6.5/hadoop-mapreduce-client-jobclient-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/hadoop/hadoop-annotations/2.6.5/hadoop-annotations-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-launcher_2.10/2.2.2/spark-launcher_2.10-2.2.2.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-network-common_2.10/2.2.2/spark-network-common_2.10-2.2.2.jar:/home/zkregex/.m2/repository/org/fusesource/leveldbjni/leveldbjni-all/1.8/leveldbjni-all-1.8.jar:/home/zkregex/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.6.5/jackson-annotations-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-network-shuffle_2.10/2.2.2/spark-network-shuffle_2.10-2.2.2.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-unsafe_2.10/2.2.2/spark-unsafe_2.10-2.2.2.jar:/home/zkregex/.m2/repository/net/java/dev/jets3t/jets3t/0.9.3/jets3t-0.9.3.jar:/home/zkregex/.m2/repository/org/apache/httpcomponents/httpcore/4.3.3/httpcore-4.3.3.jar:/home/zkregex/.m2/repository/org/apache/httpcomponents/httpclient/4.3.6/httpclient-4.3.6.jar:/home/zkregex/.m2/repository/commons-codec/commons-codec/1.8/commons-codec-1.8.jar:/home/zkregex/.m2/repository/javax/activation/activation/1.1.1/activation-1.1.1.jar:/home/zkregex/.m2/repository/mx4j/mx4j/3.0.2/mx4j-3.0.2.jar:/home/zkregex/.m2/repository/javax/mail/mail/1.4.7/mail-1.4.7.jar:/home/zkregex/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.51/bcprov-jdk15on-1.51.jar:/home/zkregex/.m2/repository/com/jamesmurty/utils/java-xmlbuilder/1.0/java-xmlbuilder-1.0.jar:/home/zkregex/.m2/repository/net/iharder/base64/2.3.8/base64-2.3.8.jar:/home/zkregex/.m2/repository/org/apache/curator/curator-recipes/2.6.0/curator-recipes-2.6.0.jar:/home/zkregex/.m2/repository/org/apache/curator/curator-framework/2.6.0/curator-framework-2.6.0.jar:/home/zkregex/.m2/repository/org/apache/zookeeper/zookeeper/3.4.6/zookeeper-3.4.6.jar:/home/zkregex/.m2/repository/com/google/guava/guava/16.0.1/guava-16.0.1.jar:/home/zkregex/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar:/home/zkregex/.m2/repository/org/apache/commons/commons-lang3/3.5/commons-lang3-3.5.jar:/home/zkregex/.m2/repository/org/apache/commons/commons-math3/3.4.1/commons-math3-3.4.1.jar:/home/zkregex/.m2/repository/com/google/code/findbugs/jsr305/1.3.9/jsr305-1.3.9.jar:/home/zkregex/.m2/repository/org/slf4j/slf4j-api/1.7.16/slf4j-api-1.7.16.jar:/home/zkregex/.m2/repository/org/slf4j/jul-to-slf4j/1.7.16/jul-to-slf4j-1.7.16.jar:/home/zkregex/.m2/repository/org/slf4j/jcl-over-slf4j/1.7.16/jcl-over-slf4j-1.7.16.jar:/home/zkregex/.m2/repository/log4j/log4j/1.2.17/log4j-1.2.17.jar:/home/zkregex/.m2/repository/org/slf4j/slf4j-log4j12/1.7.16/slf4j-log4j12-1.7.16.jar:/home/zkregex/.m2/repository/com/ning/compress-lzf/1.0.3/compress-lzf-1.0.3.jar:/home/zkregex/.m2/repository/org/xerial/snappy/snappy-java/1.1.2.6/snappy-java-1.1.2.6.jar:/home/zkregex/.m2/repository/net/jpountz/lz4/lz4/1.3.0/lz4-1.3.0.jar:/home/zkregex/.m2/repository/org/roaringbitmap/RoaringBitmap/0.5.11/RoaringBitmap-0.5.11.jar:/home/zkregex/.m2/repository/commons-net/commons-net/2.2/commons-net-2.2.jar:/home/zkregex/.m2/repository/org/scala-lang/scala-library/2.10.6/scala-library-2.10.6.jar:/home/zkregex/.m2/repository/org/json4s/json4s-jackson_2.10/3.2.11/json4s-jackson_2.10-3.2.11.jar:/home/zkregex/.m2/repository/org/json4s/json4s-core_2.10/3.2.11/json4s-core_2.10-3.2.11.jar:/home/zkregex/.m2/repository/org/json4s/json4s-ast_2.10/3.2.11/json4s-ast_2.10-3.2.11.jar:/home/zkregex/.m2/repository/org/scala-lang/scalap/2.10.0/scalap-2.10.0.jar:/home/zkregex/.m2/repository/org/scala-lang/scala-compiler/2.10.0/scala-compiler-2.10.0.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/core/jersey-client/2.22.2/jersey-client-2.22.2.jar:/home/zkregex/.m2/repository/javax/ws/rs/javax.ws.rs-api/2.0.1/javax.ws.rs-api-2.0.1.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/hk2-api/2.4.0-b34/hk2-api-2.4.0-b34.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/hk2-utils/2.4.0-b34/hk2-utils-2.4.0-b34.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/external/aopalliance-repackaged/2.4.0-b34/aopalliance-repackaged-2.4.0-b34.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/external/javax.inject/2.4.0-b34/javax.inject-2.4.0-b34.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/hk2-locator/2.4.0-b34/hk2-locator-2.4.0-b34.jar:/home/zkregex/.m2/repository/org/javassist/javassist/3.18.1-GA/javassist-3.18.1-GA.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/core/jersey-common/2.22.2/jersey-common-2.22.2.jar:/home/zkregex/.m2/repository/javax/annotation/javax.annotation-api/1.2/javax.annotation-api-1.2.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/bundles/repackaged/jersey-guava/2.22.2/jersey-guava-2.22.2.jar:/home/zkregex/.m2/repository/org/glassfish/hk2/osgi-resource-locator/1.0.1/osgi-resource-locator-1.0.1.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/core/jersey-server/2.22.2/jersey-server-2.22.2.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/media/jersey-media-jaxb/2.22.2/jersey-media-jaxb-2.22.2.jar:/home/zkregex/.m2/repository/javax/validation/validation-api/1.1.0.Final/validation-api-1.1.0.Final.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/containers/jersey-container-servlet/2.22.2/jersey-container-servlet-2.22.2.jar:/home/zkregex/.m2/repository/org/glassfish/jersey/containers/jersey-container-servlet-core/2.22.2/jersey-container-servlet-core-2.22.2.jar:/home/zkregex/.m2/repository/io/netty/netty-all/4.0.43.Final/netty-all-4.0.43.Final.jar:/home/zkregex/.m2/repository/io/netty/netty/3.9.9.Final/netty-3.9.9.Final.jar:/home/zkregex/.m2/repository/com/clearspring/analytics/stream/2.7.0/stream-2.7.0.jar:/home/zkregex/.m2/repository/io/dropwizard/metrics/metrics-core/3.1.2/metrics-core-3.1.2.jar:/home/zkregex/.m2/repository/io/dropwizard/metrics/metrics-jvm/3.1.2/metrics-jvm-3.1.2.jar:/home/zkregex/.m2/repository/io/dropwizard/metrics/metrics-json/3.1.2/metrics-json-3.1.2.jar:/home/zkregex/.m2/repository/io/dropwizard/metrics/metrics-graphite/3.1.2/metrics-graphite-3.1.2.jar:/home/zkregex/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.6.5/jackson-databind-2.6.5.jar:/home/zkregex/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.6.5/jackson-core-2.6.5.jar:/home/zkregex/.m2/repository/com/fasterxml/jackson/module/jackson-module-scala_2.10/2.6.5/jackson-module-scala_2.10-2.6.5.jar:/home/zkregex/.m2/repository/org/scala-lang/scala-reflect/2.10.6/scala-reflect-2.10.6.jar:/home/zkregex/.m2/repository/com/fasterxml/jackson/module/jackson-module-paranamer/2.6.5/jackson-module-paranamer-2.6.5.jar:/home/zkregex/.m2/repository/org/apache/ivy/ivy/2.4.0/ivy-2.4.0.jar:/home/zkregex/.m2/repository/oro/oro/2.0.8/oro-2.0.8.jar:/home/zkregex/.m2/repository/net/razorvine/pyrolite/4.13/pyrolite-4.13.jar:/home/zkregex/.m2/repository/net/sf/py4j/py4j/0.10.7/py4j-0.10.7.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-tags_2.10/2.2.2/spark-tags_2.10-2.2.2.jar:/home/zkregex/.m2/repository/org/apache/commons/commons-crypto/1.0.0/commons-crypto-1.0.0.jar:/home/zkregex/.m2/repository/org/spark-project/spark/unused/1.0.0/unused-1.0.0.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-sql_2.10/2.0.0/spark-sql_2.10-2.0.0.jar:/home/zkregex/.m2/repository/com/univocity/univocity-parsers/2.1.1/univocity-parsers-2.1.1.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-sketch_2.10/2.0.0/spark-sketch_2.10-2.0.0.jar:/home/zkregex/.m2/repository/org/apache/spark/spark-catalyst_2.10/2.0.0/spark-catalyst_2.10-2.0.0.jar:/home/zkregex/.m2/repository/org/codehaus/janino/janino/2.7.8/janino-2.7.8.jar:/home/zkregex/.m2/repository/org/codehaus/janino/commons-compiler/2.7.8/commons-compiler-2.7.8.jar:/home/zkregex/.m2/repository/org/antlr/antlr4-runtime/4.5.3/antlr4-runtime-4.5.3.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-column/1.7.0/parquet-column-1.7.0.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-common/1.7.0/parquet-common-1.7.0.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-encoding/1.7.0/parquet-encoding-1.7.0.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-generator/1.7.0/parquet-generator-1.7.0.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-hadoop/1.7.0/parquet-hadoop-1.7.0.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-format/2.3.0-incubating/parquet-format-2.3.0-incubating.jar:/home/zkregex/.m2/repository/org/apache/parquet/parquet-jackson/1.7.0/parquet-jackson-1.7.0.jar:/home/zkregex/.m2/repository/junit/junit/4.11/junit-4.11.jar:/home/zkregex/.m2/repository/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar:/home/zkregex/Desktop/ProofCarryExec/Code/zkregex/main/../dizk/dizk/target/dizk-1.0.jar:ac-1.0-SNAPSHOT.jar org.junit.runner.JUnitCore  za_interface.za.circs.tests.SimpleTest 
#java -cp bin:/usr/share/java/junit4.jar:bcprov-jdk15on-159.jar:gson.jar:ac-1.0-SNAPSHOT.jar:zkregex-1.0-SNAPSHOT.jar    org.junit.runner.JUnitCore  za_interface.za.circs.tests.RandTest
