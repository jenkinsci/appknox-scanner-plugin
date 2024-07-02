//Example pipeline script for customers app build using gradle.
pipeline {
    agent any
    parameters {
        choice(name: 'RISK_THRESHOLD', choices: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], description: 'Risk Threshold')
    }
    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/yourgithub/reponame'
            }
        }
        stage('Build App') {
            steps {
                // Build the app using specific Gradle version
                script {
                    if (isUnix()) {
                        sh './gradlew build'
                        FILE_PATH = "${WORKSPACE}/app/build/outputs/apk/debug/app-debug.apk"
                    } else {
                        bat './gradlew build'
                        FILE_PATH = "${WORKSPACE}\\app\\build\\outputs\\apk\\debug\\app-debug.apk"
                    }
                    echo "Found APK: ${FILE_PATH}"
                }
            }
        }
        stage('Appknox Scan') {
            steps {
                script {
                        // Perform Appknox scan using AppknoxPlugin
                        step([
                            $class: 'AppknoxPlugin',
                            credentialsId: 'appknox-access-token', //Specify the Appknox Access Token ID. Ensure the ID matches with the ID given while configuring Appknox Access Token in the credentials.
                            filePath: FILE_PATH,
                            riskThreshold: params.RISK_THRESHOLD.toUpperCase()
                        ])
                    
                }
            }
        }
    }
}
