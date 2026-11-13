package federation

import "errors"

type InputError struct{ Message string }

func (e *InputError) Error() string   { return e.Message }
func inputError(message string) error { return &InputError{Message: message} }

var ErrHubRefused = errors.New("hub refused this credential (revoked, unknown, or wrong archive)")
