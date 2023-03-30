pipeline {
    agent {
        node {
            label 'Docker-Maven-Agent'
        }
    }

	environment {
		BLACKDUCK_API_TOKEN = credentials("BLACKDUCK_API_TOKEN")
	
		BD_AUTH_ACCEPT = "application/vnd.blackducksoftware.user-4+json"
		BD_PROJECT_ACCEPT = "application/vnd.blackducksoftware.project-detail-4+json"
		BD_VERSION_ACCEPT = "application/vnd.blackducksoftware.project-detail-5+json"
		BD_AUTH_API = "api/tokens/authenticate"
		BD_PROJECT_API = "api/projects"
		BD_VERSION_API = "api/projects/{projectId}/versions"

		JENKINS_CREDS = credentials("USER_JENKINS")
		
		JIRA_API_AUTH = credentials("JIRA_ENCRYPTED_USER_PASS")
		JIRA_CREATE_API = "rest/api/2/issue"
		// Git debugging purpose
		//GIT_CURL_VERBOSE=1
		//GIT_TRACE=1
	}

	options {
	    gitLabConnection("GitLab Connection")
	}

	stages {
		stage("gitlab-cloning") {
			steps {
				echo "Cloning from repo"
	            //git branch: 'main',
                sh 'git clone "http://${JENKINS_CREDS}@${GITLAB_URL}"/root/insecure-bank.git'
				updateGitlabCommitStatus name: "build", state: "pending"
			}
		}

		stage("build") {
			steps {
				echo "Building by Maven"
				updateGitlabCommitStatus name: "build", state: "running"
				dir('insecure-bank') {
					sh 'mvn -version'
					sh 'mvn clean package'
				}
			}
		}

		stage("test-SCA") {
			steps {
				echo "Test by SCA"
				sh '''curl -s -o ./synopsys-detect-${DETECT_VERSION}.jar \
					-L "https://sig-repo.synopsys.com/bds-integrations-release/com/synopsys/integration/synopsys-detect/${DETECT_VERSION}/synopsys-detect-${DETECT_VERSION}.jar"
				'''
				sh 'chmod +x ./synopsys-detect-${DETECT_VERSION}.jar' 
				sh '''java -jar ./synopsys-detect-${DETECT_VERSION}.jar \
						--blackduck.url="${BLACKDUCK_URL}" \
						--detect.project.name="${JOB_BASE_NAME}" \
						--detect.project.version.name="${BUILD_NUMBER}" \
						--detect.source.path="./insecure-bank" \
						--detect.wait.for.results="true" \
						--detect.timeout="${BLACKDUCK_TIMEOUT}" \
						--blackduck.api.token="${BLACKDUCK_API_TOKEN}" \
						--blackduck.trust.cert="true" \
						--logging.level.com.synopsys.integration="DEBUG"
				'''
			}
		}

		stage("validate-SCA-results") {
			steps {
				echo "Validate SCA Results"
				script {
					// BD Authorization
					// TODO: Convert th httpRequest block to a method
					def response = httpRequest(url: "$BLACKDUCK_URL$BD_AUTH_API",
						httpMode: "POST",
						ignoreSslErrors: true, 
						customHeaders: [
							[name: "Accept", value: "$BD_AUTH_ACCEPT" ],
							[name: "Authorization", value: "token $BLACKDUCK_API_TOKEN"]]
					)
					def resMap = readJSON text: response.content
					def bearer = resMap.bearerToken
					assert (bearer != null) && (bearer != "")

					// BD search the project and fetch the href for the versions
					def href = ""
					response = httpRequest(url: "$BLACKDUCK_URL$BD_PROJECT_API?limit=100&q=name:$JOB_BASE_NAME",
						httpMode: "GET",
						ignoreSslErrors: true, 
						customHeaders: [
							[name: "Accept", value: "$BD_PROJECT_ACCEPT"],
							[name: "Authorization", value: "Bearer $bearer"]]
					)
					resMap = readJSON text: response.content
					resMap.items[0]._meta.links.find {
						if (it["rel"] == "versions") {
						    href = it["href"]
						}
					}
					assert (href != null) && (href != "")
					
					// BD search the version
					response = httpRequest(url: "$href?limit=100&q=versionName:$BUILD_NUMBER",
						httpMode: "GET",
						ignoreSslErrors: true, 
						customHeaders: [
							[name: "Accept", value: "$BD_VERSION_ACCEPT"],
							[name: "Authorization", value: "Bearer $bearer"]]
					)
					resMap = readJSON text: response.content

					// BD get the version-risk-profile and review the returned risk profile
					resMap.items[0]._meta.links.find {
						if (it["rel"] == "version-risk-profile") {
							href = it["href"]
						}
					}
					assert (href != null) && (href != "")
					response = httpRequest(url: "$href?limit=100",
						httpMode: "GET",
						ignoreSslErrors: true, 
						customHeaders: [
							[name: "Accept", value: "$BD_VERSION_ACCEPT" ],
							[name: "Authorization", value: "Bearer $bearer"]]
					)
					def versionVulns = checkVersionVulns(response.content)

					// BD get the version's policy status and review the returned policy status
					resMap.items[0]._meta.links.find {
						if (it["rel"] == "policy-status") {
							href = it["href"]
						}
					}
					assert (href != null) && (href != "")
					response = httpRequest(url: "$href?limit=100",
						httpMode: "GET",
						ignoreSslErrors: true, 
						customHeaders: [
							[name: "Accept", value: "application/json" ],
							[name: "Authorization", value: "Bearer $bearer"]]
					)
					def versionPolicy = checkVersionPolicy(response.content)

					// File a JIRA ticket if either medium-critical vulns or policy violations are found
					if (versionVulns || versionPolicy) {
						def summary = "Dummy bug ticket for project: $JOB_BASE_NAME, version: $BUILD_NUMBER"
						fileJiraTicket(summary)
					}
				}
			}
		}
	}

	post {
	    // Clean after build whenever the build was successful or failed
		always {
			script {
				if (getContext(hudson.FilePath)) {
					deleteDir()
				}
			}
		}
		success {
			updateGitlabCommitStatus name: "build", state: "success"
		}
		failure {
		    updateGitlabCommitStatus name: "build", state: "failed"
		}
	}
}

/*
	Check version's vulnerabilities
	returns: true for MEDIUM to CRITICAL vulns, false for otherwise
*/
boolean checkVersionVulns(String content) {
	def resMap = readJSON text: content
	resMap.categories.VULNERABILITY.find {
		if ((it.key == "MEDIUM"
			|| it.key == "HIGH"
			|| it.key == "CRITICAL")
			&& it.value >= 1) {
			println("Found vulnerabilities with severity: " + it.key +
				" and number: " + it.value)
			return true
		} else {
			return false
		}
	}
}

/*
	Check version's policy violation
	returns: true for !"NOT_IN_VIOLATION" or false otherwise
*/
boolean checkVersionPolicy(String content) {
	def resMap = readJSON text: content
	if (resMap.overallStatus != "NOT_IN_VIOLATION") {
		return true
	}
	return false
}

/*
	File a Jira bug ticket
	returns: N/A
*/
void fileJiraTicket(String summary) {
	def bodyMap = ["fields": [
			"project": [
				"key": "MKDEV"
			],
			"summary": "$summary",
			"issuetype": [
				"name": "Bug"
			],
			"assignee": [
				"name": "team-gamma-jira"
			],
			"reporter": [
				"name": "team-gamma-jira"
			],
			"description": "A bug ticket creation for testing purpose"
		]
	]
	def bodyJson = writeJSON returnText: true, json: bodyMap
	response = httpRequest(url: "$JIRA_URL$JIRA_CREATE_API",
		httpMode: "POST",
		customHeaders: [
			[name: "Content-Type", value: "application/json" ],
			[name: "Authorization", value: "Basic $JIRA_API_AUTH"]],
		requestBody: bodyJson
	)
	println("Response is $response.content")
}
