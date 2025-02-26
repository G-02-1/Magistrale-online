FROM openjdk:8-jdk-alpine
MAINTAINER lbelcastro@dimes.unical.it
COPY policy.all /usr/lib/jvm/java-1.8-openjdk/jre/lib/security/java.policy
COPY sisdis-1.0-SNAPSHOT.jar /app.jar
ENV JAVA_OPTS="-Xms1G -Xmx1G"
EXPOSE 1099
ENTRYPOINT ["java","-Djava.rmi.server.useCodebaseOnly=false","-Djava.security.policy=/policy.all","-jar","/app.jar", "computeEngineCodebase.server.ComputeEngineServer"]
