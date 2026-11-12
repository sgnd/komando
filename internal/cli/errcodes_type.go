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

// sharedCode is a code more than one kind of item gives today, with the
// error.thing values that tell them apart (S-8.3). Contract 2 gives each
// thing its own code (Split); until then the code stays and agents read
// error.thing.
type sharedCode struct {
	Code   string
	Things []string
	Split  string // the codes contract 2 gives instead
}

// sharedCodes is the split list of C-E02. TestSharedCodes checks that
// every error.thing the source sets is listed here.
var sharedCodes = []sharedCode{
	{"KEY_NOT_FOUND", []string{"ssh_key", "cache_key"}, "SSH_KEY_NOT_FOUND, CACHE_KEY_NOT_FOUND"},
	{"CONN_NOT_FOUND", []string{"conn", "selector"}, "CONN_NOT_FOUND, TARGET_EMPTY"},
	{"NOT_FOUND", []string{"swarm_service", "swarm_stack", "swarm_node", "swarm_task", "swarm_config", "swarm_secret", "swarm_network", "docker_object", "cache_info_section"},
		"SWARM_SERVICE_NOT_FOUND, SWARM_STACK_NOT_FOUND, SWARM_OBJECT_NOT_FOUND, DOCKER_OBJECT_NOT_FOUND, CACHE_SECTION_NOT_FOUND"},
	{"REGISTRY_NOT_FOUND", []string{"repository", "image_tag"}, "REPOSITORY_NOT_FOUND, IMAGE_NOT_FOUND"},
	{"K8S_NOT_FOUND", []string{"k8s_object", "k8s_pod", "k8s_container"}, "K8S_NOT_FOUND, K8S_POD_NOT_FOUND, K8S_CONTAINER_NOT_FOUND"},
}

// sameAs is a code that means the same as another one (S-8.3, C-E03).
// Both stay in contract 1, since agents branch on them; a new error uses
// Survivor, and contract 2 keeps only that one.
type sameAs struct {
	Codes    []string // the codes that mean the same, survivor first
	Survivor string
	Note     string
}

// sameAsCodes: the same-meaning codes. TestSameAsCodes checks each is in
// the catalog; error-codes.md shows the table.
var sameAsCodes = []sameAs{
	// a protected server and a protected conn or VPN stop the same way
	{[]string{"PROTECTED_TARGET", "PROTECTED_HOST"}, "PROTECTED_TARGET", "a protected item needs a person's yes (--yes); PROTECTED_HOST is the server case"},
	// --reveal stopped: REVEAL_NEEDS_HUMAN is the case no flag lifts
	{[]string{"REVEAL_NEEDS_PERSON", "REVEAL_NEEDS_HUMAN"}, "REVEAL_NEEDS_PERSON", "--reveal needs a person; REVEAL_NEEDS_HUMAN is the case where no window can ask one, so only a person at a terminal can run it"},
	// a selector that picks nothing
	{[]string{"TARGET_EMPTY", "NO_MATCHING_TARGETS", "CONN_NOT_FOUND"}, "TARGET_EMPTY", "the target picked nothing the command can use; CONN_NOT_FOUND counts only with error.thing selector"},
	// cannot reach a place
	{[]string{"CONN_UNREACHABLE", "CONNECT_FAILED"}, "CONN_UNREACHABLE", "komando could not reach the address"},
	// a program komando ran exited non-zero
	{[]string{"TOOL_FAILED", "FAILED"}, "TOOL_FAILED", "a program komando ran (kubectl, a dump tool) failed; its words follow"},
	// storage download of a folder
	{[]string{"IS_A_DIRECTORY", "USAGE"}, "IS_A_DIRECTORY", "storage download of a folder without -r gives USAGE today; contract 2 gives IS_A_DIRECTORY, as fs cat does"},
}
