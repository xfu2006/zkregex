# RUN getenv.py if there are new dependencies OR if 
# it is the first time to run

mvn package  -DskipTests
#python getenv.py
