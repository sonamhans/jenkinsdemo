pipeline {
  agent any
  parameters {
      string(name: 'docker_images', description: 'Enter the docker images names (comma separated) example - image1,image2')
  }
  environment {
        TRIVY_REPORT_JSON = 'trivy_report.json'
        GITHUB_REPO = 'sonamhans/jenkinsdemo'
        GITHUB_PROJECT = 'jenkinsdemo'
  }

  stages {
        stage('Scan Docker Image with Trivy') {
            steps {
                script {
                    def docker_images = params.docker_images
                    def scanTimestamp = new Date().format("yyyy-MM-dd_HH-mm-ss")

                    // Pull trivy image
                    sh "docker pull aquasec/trivy"

                    // Initialize the JSON report file
                    writeFile(file: "${TRIVY_REPORT_JSON}", text: '[]')

                    // Split the string into an array using comma as the delimiter
                    def substrings = docker_images.split(',')

                    substrings.each { imageName ->

                        try {
                            echo "Pulling Docker image: ${imageName}"
                            sh "docker pull ${imageName}"
                        } catch (Exception e) {
                            error "Failed to pull Docker image: ${imageName}"
                        }

                        try {
                            echo "Scanning Docker image with Trivy: ${imageName}"
                            // Scan the docker image with Trivy and capture the JSON output
                            def trivyOutput = sh(script: "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --format json ${imageName}", returnStdout: true)
                            def existingContent = readFile("${TRIVY_REPORT_JSON}")
                            def existingJson = new groovy.json.JsonSlurperClassic().parseText(existingContent)
                            def newJson = new groovy.json.JsonSlurperClassic().parseText(trivyOutput)
                            existingJson.add(newJson)
                            def updatedJsonContent = groovy.json.JsonOutput.toJson(existingJson)
                            writeFile(file: "${TRIVY_REPORT_JSON}", text: updatedJsonContent)
                        } catch (Exception e) {
                            error "Trivy scan failed for Docker image: ${imageName}"
                        }
                    }
                    // Set the CSV report name with images and timestamp
                    env.TRIVY_REPORT_CSV = "trivy_report_${scanTimestamp}.csv"
                }
            }
        }

        stage('Convert JSON to CSV') {
            steps {
                script {
                    // Verify that the JSON file exists before attempting to read it
                    if (fileExists("${TRIVY_REPORT_JSON}")) {
                        // Read the JSON content
                        def jsonContent = readFile("${TRIVY_REPORT_JSON}")
                        def json = new groovy.json.JsonSlurperClassic().parseText(jsonContent)

                        // Define the CSV columns
                        def csvData = "Package name,Severity,Version,Fixed in version,Description,CVE ID,Source\n"

                        // Create a map to consolidate vulnerabilities
                        def vulnMap = [:]

                        // Function to escape CSV fields
                        def escapeCsv = { field ->
                            if (field == null) {
                                return ""
                            }
                            def escapedField = field.toString().replaceAll('"', '""')
                            if (escapedField.contains(',') || escapedField.contains('\n')) {
                                escapedField = "\"${escapedField}\""
                            }
                            return escapedField
                        }

                        // Parse JSON and consolidate vulnerabilities
                        json.each { result ->
                            result.Results.each { res ->
                                res.Vulnerabilities?.each { vuln ->
                                    def key = "${vuln.PkgName}-${vuln.VulnerabilityID}"
                                    if (vulnMap.containsKey(key)) {
                                        vulnMap[key].sources.add(result.ArtifactName)
                                    } else {
                                        vulnMap[key] = [
                                            pkgName: vuln.PkgName,
                                            severity: vuln.Severity,
                                            version: vuln.InstalledVersion,
                                            fixedVersion: vuln.FixedVersion,
                                            description: vuln.Description,
                                            cveId: vuln.VulnerabilityID,
                                            sources: [result.ArtifactName]
                                        ]
                                    }
                                }
                            }
                        }

                        // Convert consolidated vulnerabilities to CSV
                        vulnMap.each { key, vuln ->
                            csvData += "${escapeCsv(vuln.pkgName)},${escapeCsv(vuln.severity)},${escapeCsv(vuln.version)},${escapeCsv(vuln.fixedVersion)},${escapeCsv(vuln.description)},${escapeCsv(vuln.cveId)},${escapeCsv(vuln.sources.join('; '))}\n"
                        }

                        // Write the CSV content to a file
                        writeFile(file: "${TRIVY_REPORT_CSV}", text: csvData)
                    } else {
                        error("JSON report file not found: ${TRIVY_REPORT_JSON}")
                    }
                }
            }
        }

        stage('Upload CSV to GitHub') {
            steps {
                script {

                    // Clone the repository
                    sh "git clone https://github.com/${GITHUB_REPO}.git"

                    // Move the CSV file to the repository directory
                    sh "mv ${env.TRIVY_REPORT_CSV} ${GITHUB_PROJECT}/"

                    // Change to the repository directory
                    dir(GITHUB_PROJECT) {
                        sh 'git add .'
                        sh 'git commit -m "Add Trivy scan report"'
                        sh 'ssh -T git@github.com'
                        sh 'git push'
                    }
                }
            }
        }
  }

  post {
      always {
          cleanWs()
      }
  }
}