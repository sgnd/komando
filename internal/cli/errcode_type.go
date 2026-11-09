package cli

// errorCode is one entry of the error catalog `komando schema` gives
// (error_codes): the code, the exit code that goes with it, an example
// message (values shown as …) and the usual next step. errcodes.go holds
// the catalog; TestErrorCodeCatalog keeps it in step with the source.
type errorCode struct {
	Code    string `json:"code"`
	Exit    int    `json:"exit"`
	Example string `json:"example,omitempty"`
	Hint    string `json:"hint,omitempty"`
}
