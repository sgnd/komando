package out

// The Printer's setters for meta fields that are not the run's result:
// a skipped dry-run step, the body's SHA-256, a newly pinned host key.

// NotSimulated records a step a dry run left out because trying it would
// make it (meta.not_simulated).
func (p *Printer) NotSimulated(what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notSim = append(p.notSim, what)
}

// BodySHA256 records the SHA-256 (hex) of the body the command sends,
// for meta.body_sha256.
func (p *Printer) BodySHA256(sum string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bodySum = sum
}

// HostKeyPinned records a host key trusted on first use, for
// meta.host_keys_pinned (a person reads it on stderr).
func (p *Printer) HostKeyPinned(k HostKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinned = append(p.pinned, k)
}
