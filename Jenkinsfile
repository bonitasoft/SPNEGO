timestamps {
    ansiColor('xterm') {
        node {
            stage('Setup') {
                checkout scm
            }

            stage('Build') {
                try {
                    sh './mvnw clean verify'
                    archiveArtifacts '**/target/bonita-spnego-*.jar'
                }
            }
        }
    }
}
