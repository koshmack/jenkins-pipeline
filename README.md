# MK-jenkins-pipeline
Jenkins Pipeline script file and other configuration files are shared as sample code for Jenkins pipeline. Currently only Dockerfile is uploaded as example for a containerized Jenkins agent to execute Maven builds. 

## Scope
Currently only Black Duck is invoked on the pipeline but the aim is to use other SIG products. TODO

## How to use?
Jenkins Pipelines are invoked from various triggers. Refer to the Jenkins pipeline documents such as https://www.jenkins.io/doc/book/pipeline/running-pipelines/

If you are interested in hooking your Jenkins Pipelines to SCM such as Github or GitLab and the Pipeline script is executed by the trigger from the SCM, please refer to the SCM document. For GitLab integration, here is the pointer. https://docs.gitlab.com/ee/integration/jenkins.html
