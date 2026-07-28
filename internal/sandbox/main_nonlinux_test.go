//go:build !linux

package sandbox

import "testing"

func configureIntegrationManager(t testing.TB, manager *Manager) {
	t.Helper()
}
