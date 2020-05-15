
#!/bin/sh
set -ue

wget https://github.com/federicodotta/RSyntaxTextArea/releases/download/2.6.1.edited/rsyntaxtextarea-2.6.1.edited.jar
mvn install:install-file -Dfile=rsyntaxtextarea-2.6.1.edited.jar -DgroupId=com.fifesoft -DartifactId=rsyntaxtextarea -Dversion=2.6.1.edited -Dpackaging=jar
#gradle fatJar
mvn package
