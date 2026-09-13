package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParityDecodersRejectNilEncodings(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{
			name: "history",
			decode: func() error {
				_, err := decodeParityHistoryEntry(nil)
				return err
			},
		},
		{
			name: "relationship",
			decode: func() error {
				_, err := decodeParityRelationshipDependency(nil, []byte("lookup"))
				return err
			},
		},
		{
			name: "request",
			decode: func() error {
				_, err := decodeParityRequest(nil)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, test.decode())
		})
	}
}
