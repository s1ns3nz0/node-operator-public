package configprovider

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
)

func TestLegacyExpandConverterResolver(t *testing.T) {
	t.Setenv("CWA_LEGACY_EXPAND", "expanded")
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "bare variable", input: "$CWA_LEGACY_EXPAND", want: "expanded"},
		{name: "braced variable", input: "${CWA_LEGACY_EXPAND}", want: "expanded"},
		{name: "env provider variable", input: "${env:CWA_LEGACY_EXPAND}", want: "expanded"},
		{name: "bare capture group is rejected", input: "$1", wantErr: "invalid name"},
		{name: "braced capture group is rejected", input: "${1}", wantErr: "invalid name"},
		{name: "translated capture group survives both passes", input: "$$$$1", want: "$1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte("value: "+strconv.Quote(tt.input)+"\n"), 0o600))

			settings := GetSettings([]string{configPath}, zap.NewNop())
			resolver, err := confmap.NewResolver(settings.ResolverSettings)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, resolver.Shutdown(context.Background())) })

			resolved, err := resolver.Resolve(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, resolved.Get("value"))
		})
	}
}
