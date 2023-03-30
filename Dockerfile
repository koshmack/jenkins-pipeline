FROM jenkins/slave:latest-jdk11

ARG MVN_VERSION=3.8.4

# switch user to write access to the folder which was created by the source "FROM"
USER root

RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/${MVN_VERSION}/binaries/apache-maven-${MVN_VERSION}-bin.tar.gz | \
	tar -xvz --directory /usr/local/ \
	&& ln -sf /usr/local/apache-maven-${MVN_VERSION}/bin/mvn /usr/local/bin/mvn
	
USER jenkins

ENV PATH=/usr/local/bin/mvn:$PATH
