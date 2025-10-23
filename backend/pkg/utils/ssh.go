package utils

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient handles SSH connections and command execution
type SSHClient struct {
	Host     string
	Port     int
	Username string
	Password string
	SSHKey   string
	Timeout  time.Duration
}

// Connect establishes SSH connection
func (c *SSHClient) Connect() (*ssh.Client, error) {
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
		Timeout:         c.Timeout,
	}

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	return ssh.Dial("tcp", addr, config)
}

// ExecuteCommand runs a command on remote server
func (c *SSHClient) ExecuteCommand(command string) (string, string, error) {
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

// TestConnection verifies SSH connectivity
func (c *SSHClient) TestConnection() error {
	client, err := c.Connect()
	if err != nil {
		return err
	}
	defer client.Close()
	return nil
}

