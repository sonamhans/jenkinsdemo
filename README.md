# Trivy Scanner

Jenkins will take docker images as a parameter before running the pipeline. example value = image1, image2, image3

All the docker images will be pulled and scanned via trivy. Consolidated scan result will be kept in trivy_report_${scanTimestamp}.csv where scanTimestamp will be current timestamp in yyyy-MM-dd_HH-mm-ss.

Generated CSV will then be pushed with same git repository where Jenkinsfile exist which is the same repository you are in.

example generated CSV -> trivy_report_2025-03-16_21-32-42.csv

# System setup
Following installation needed on environment - 
Jenkins 
Docker
Git 