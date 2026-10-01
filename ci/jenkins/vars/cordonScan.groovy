// Cordon supply-chain scanning as a Jenkins shared library step.
//
//   @Library('cordon@v0.5.0') _
//   cordonScan(failOn: 'high')
//
// The scanner is installed hash-verified from the pin committed at the library's tag. The exit
// code is captured, reports are always archived, and only then is the build marked: a failed
// stage with no report tells nobody anything.

def call(Map options = [:]) {
    def version = options.get('version', '0.5.0')
    def severity = options.get('severity', 'low')
    def failOn = options.get('failOn', 'high')
    def upload = options.get('upload', false)

    if (!(version ==~ /^[0-9]+\.[0-9]+\.[0-9]+$/)) { error("cordonScan: version is not a version: ${version}") }
    if (!(severity in ['info', 'low', 'medium', 'high', 'critical'])) { error("cordonScan: bad severity") }
    if (!(failOn in ['info', 'low', 'medium', 'high', 'critical', 'none'])) { error("cordonScan: bad failOn") }

    withEnv(["CORDON_VERSION=${version}", "CORDON_SEVERITY=${severity}", "CORDON_FAIL_ON=${failOn}", "CORDON_UPLOAD=${upload}"]) {
        sh '''
            set -eu
            python3 -m venv .cordon-venv
            curl -fsSLo .cordon-requirements.txt \
              "https://raw.githubusercontent.com/Threx-code/cordon/v${CORDON_VERSION}/ci/requirements.txt"
            .cordon-venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --no-deps \
              -r .cordon-requirements.txt
        '''
        def code = sh(returnStatus: true, script: '''
            set -- scan . --severity "$CORDON_SEVERITY" --fail-on "$CORDON_FAIL_ON" --no-color \
              --format text --format junit:cordon-junit.xml --format sarif:cordon.sarif
            # Jenkins has no built-in OIDC issuer; with the OIDC provider plugin, bind its token to
            # CORDON_ID_TOKEN (audience `cordon`) in the calling pipeline to upload.
            [ "$CORDON_UPLOAD" = "true" ] && set -- "$@" --upload
            .cordon-venv/bin/cordon-scanner "$@"
        ''')
        junit allowEmptyResults: true, testResults: 'cordon-junit.xml'
        archiveArtifacts allowEmptyArchive: true, artifacts: 'cordon.sarif, cordon-junit.xml'
        if (code == 1) { unstable("Cordon reported findings at or above ${failOn}") }
        else if (code == 4) { unstable("Cordon could not examine everything (exit 4)") }
        else if (code != 0) { error("Cordon failed with exit code ${code}") }
    }
}
