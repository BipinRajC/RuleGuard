package ssh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client handles SSH connections and command execution
type Client struct {
	Host     string
	Port     int
	Username string
	Password string
	SSHKey   string
	Timeout  time.Duration
}

// NewClient creates a new SSH client
func NewClient(host string, port int, username, password, sshKey string) *Client {
	return &Client{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		SSHKey:   sshKey,
		Timeout:  30 * time.Second,
	}
}

// Connect establishes SSH connection
func (c *Client) Connect() (*ssh.Client, error) {
	var authMethod ssh.AuthMethod

	if c.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.SSHKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}
		authMethod = ssh.PublicKeys(signer)
	} else {
		authMethod = ssh.Password(c.Password)
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.Timeout,
	}

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	return ssh.Dial("tcp", addr, config)
}

// ExecuteCommand runs a command on remote server
func (c *Client) ExecuteCommand(command string) (string, string, error) {
	client, err := c.Connect()
	if err != nil {
		return "", "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(command)
	return stdout.String(), stderr.String(), err
}

// ExecuteScript uploads and runs a bash script on remote server
func (c *Client) ExecuteScript(scriptPath string, args ...string) (string, error) {
	client, err := c.Connect()
	if err != nil {
		return "", err
	}
	defer client.Close()

	// Read script from local file
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("failed to read script: %w", err)
	}

	// Generate remote path
	scriptName := filepath.Base(scriptPath)
	remoteScriptPath := fmt.Sprintf("/tmp/%s", scriptName)

	// Upload script using fish-compatible command
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
	for _, arg := range args {
		execCmd += " " + arg
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

// TestConnection verifies SSH connectivity
func (c *Client) TestConnection() error {
	client, err := c.Connect()
	if err != nil {
		return err
	}
	defer client.Close()
	return nil
}

// DetectOS detects the operating system of the remote server
func (c *Client) DetectOS() (string, error) {
	stdout, _, err := c.ExecuteCommand("cat /etc/os-release | grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' | head -1 | cut -d '=' -f2 | tr -d '\"'")
	if err != nil {
		return "", fmt.Errorf("failed to detect OS: %w", err)
	}
	return stdout, nil
}
