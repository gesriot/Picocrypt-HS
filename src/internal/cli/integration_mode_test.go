package cli

import "testing"

func TestCLIIntegrationEnabled(t *testing.T) {
	t.Setenv("PICOCRYPT_RUN_CLI_INTEGRATION", "")
	if cliIntegrationEnabled() {
		t.Fatal("cliIntegrationEnabled should be false by default")
	}

	t.Setenv("PICOCRYPT_RUN_CLI_INTEGRATION", "1")
	if !cliIntegrationEnabled() {
		t.Fatal("cliIntegrationEnabled should be true when env var is 1")
	}

	t.Setenv("PICOCRYPT_RUN_CLI_INTEGRATION", "true")
	if cliIntegrationEnabled() {
		t.Fatal("cliIntegrationEnabled should only accept the value 1")
	}
}
