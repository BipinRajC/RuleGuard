package utils

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// ExecuteScript uploads and runs a bash script on remote server
func ExecuteScript(client *ssh.Client, scriptPath string, args ...string) (string, error) {
	// Read script from local file
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("failed to read script: %w", err)
	}

	// Generate remote path
	remoteScriptPath := fmt.Sprintf("/tmp/%s", scriptPath)

	// Upload script
	uploadCmd := fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF\nchmod +x %s",
		remoteScriptPath, string(scriptContent), remoteScriptPath)

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	_, err = session.CombinedOutput(uploadCmd)
	session.Close()

	if err != nil {
		return "", fmt.Errorf("failed to upload script: %w", err)
	}

	// Execute script with arguments
	execCmd := remoteScriptPath
	if len(args) > 0 {
		for _, arg := range args {
			execCmd += " " + arg
		}
	}

	session, err = client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(execCmd)

	// Cleanup
	cleanupSession, _ := client.NewSession()
	if cleanupSession != nil {
		cleanupSession.CombinedOutput(fmt.Sprintf("rm -f %s", remoteScriptPath))
		cleanupSession.Close()
	}

	return string(output), err
}

