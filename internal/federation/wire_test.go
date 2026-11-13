package federation

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestDecodeBatchRejectsExcessAndUnknownPayloadFields(t *testing.T) {
	_, err := DecodeBatch([]byte(`{"protocol":1,"spoke_instance":"s","share_uid":"x","epoch":1,"sequence":1,"records":[` + strings.Repeat(`{},`, 1000) + `{}` + `]}`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid federation batch")
	_, err = DecodeBatch([]byte(`{"protocol":1,"spoke_instance":"s","share_uid":"x","epoch":1,"sequence":1,"records":[{"record_uid":"a","kind":"session_summary","hash":"x","payload":{"cwd":"private"}}]}`))
	require.Error(t, err)
}

func TestDecodeBatchRejectsUnknownEnvelopeAndOversize(t *testing.T) {
	_, err := DecodeBatch([]byte(`{"protocol":1}`))
	require.Error(t, err)
	_, err = DecodeBatch([]byte(`{"records":[],"records":[]}`))
	require.Error(t, err)

	_, err = DecodeBatch([]byte(`{"protocol":1,"spoke_instance":"s","share_uid":"x","epoch":1,"sequence":1,"records":[],"unexpected":true}`))
	require.Error(t, err)
	_, err = DecodeBatch([]byte(strings.Repeat(" ", (16<<20)+1)))
	require.Error(t, err)
}
