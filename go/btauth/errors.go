package btauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Error codes (spec Appendix A) used by this package.
const (
	CodeMalformed              = "tw.auth_malformed"
	CodeWrongReceiver          = "tw.auth_wrong_receiver"
	CodeStale                  = "tw.auth_stale"
	CodeBadSignature           = "tw.auth_bad_signature"
	CodeReplayed               = "tw.auth_replayed"
	CodePayloadTooLarge        = "tw.payload_too_large"
	CodeReplayStoreUnavailable = "tw.replay_store_unavailable"
	CodeHandlerError           = "tw.handler_error"
	CodeHandlerTimeout         = "tw.handler_timeout"
	CodeRateLimited            = "tw.rate_limited"
	CodeInternal               = "tw.internal"

	// Client-side codes (validator side, spec Appendix A).
	CodeBadResponseSignature = "tw.bad_response_signature"
	CodeResponseTooLarge     = "tw.response_too_large"
	CodeTimeout              = "tw.timeout"
	CodeConnectError         = "tw.connect_error"
	CodeInvalidResponse      = "tw.invalid_response"
)

type errorSpec struct {
	status  int
	message string
}

// catalogue holds the server-side rows of Appendix A with the fixed public
// messages of the Python kit (tensorwire.errors).
var catalogue = map[string]errorSpec{
	"tw.internal":                 {500, "internal error"},
	"tw.rate_limited":             {429, "rate limit exceeded"},
	"tw.payload_too_large":        {413, "request body exceeds the size limit"},
	"tw.auth_malformed":           {401, "malformed authentication headers"},
	"tw.auth_wrong_receiver":      {401, "request was signed for a different receiver"},
	"tw.auth_stale":               {401, "request nonce is outside the freshness window"},
	"tw.auth_bad_signature":       {401, "signature does not verify"},
	"tw.auth_replayed":            {401, "request was already accepted"},
	"tw.forbidden_denied":         {403, "caller is denied"},
	"tw.forbidden_not_registered": {403, "caller is not registered on this subnet"},
	"tw.forbidden_not_validator":  {403, "caller has no validator permit"},
	"tw.forbidden_low_stake":      {403, "caller stake is below the minimum"},
	"tw.forbidden_blacklisted":    {403, "caller is blacklisted"},
	"tw.invalid_request":          {422, "request body does not match the route model"},
	"tw.handler_error":            {500, "handler failed"},
	"tw.metagraph_stale":          {503, "metagraph snapshot is too old to admit this caller"},
	"tw.replay_store_unavailable": {503, "replay protection store is unavailable"},
	"tw.handler_timeout":          {504, "handler timed out"},
	"tw.legacy_auth_failed":       {401, "legacy v10 authentication failed"},
	"tw.legacy_disabled":          {410, "legacy v10 requests are no longer accepted"},
	"tw.sidecar_unauthorized":     {401, "sidecar token missing or wrong"},
}

// Error is a refusal with a stable tw.* code. Status is its HTTP status
// (0 for client-side codes). Message is the fixed public message, safe to
// send to an unauthenticated caller; Detail says more for logs only.
type Error struct {
	Code    string
	Status  int
	Message string
	Detail  string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
	return e.Code + ": " + e.Message
}

// NewError returns the Appendix A error for code. Unknown codes become
// tw.internal (500), so a typo can never produce a 2xx.
func NewError(code, detail string) *Error {
	spec, ok := catalogue[code]
	if !ok {
		if code == CodeBadResponseSignature || code == CodeResponseTooLarge ||
			code == CodeTimeout || code == CodeConnectError || code == CodeInvalidResponse {
			return &Error{Code: code, Message: code, Detail: detail}
		}
		code, spec = CodeInternal, catalogue[CodeInternal]
	}
	return &Error{Code: code, Status: spec.status, Message: spec.message, Detail: detail}
}

// StatusOf returns the HTTP status of an Appendix A code (500 if unknown).
func StatusOf(code string) int {
	if spec, ok := catalogue[code]; ok {
		return spec.status
	}
	return http.StatusInternalServerError
}

type errorBody struct {
	Error struct {
		Code      string  `json:"code"`
		Message   string  `json:"message"`
		RequestID *string `json:"request_id"`
	} `json:"error"`
}

// ErrorBody is the JSON body of every error response, in every language:
// {"error": {"code": ..., "message": ..., "request_id": ...}}.
func ErrorBody(e *Error, requestID string) []byte {
	var b errorBody
	b.Error.Code, b.Error.Message = e.Code, e.Message
	if requestID != "" {
		b.Error.RequestID = &requestID
	}
	out, _ := json.Marshal(b) // a struct of strings always marshals
	return out
}
