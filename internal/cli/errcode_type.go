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
