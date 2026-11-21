//go:build !linux && !darwin

package engine

// Other systems have no process lookup here: the environment alone says
// who the caller is.
func parentPID() int { return 0 }

type noProcs struct{}

func osProcs() ProcTable { return noProcs{} }

func (noProcs) Proc(int) (Proc, bool) { return Proc{}, false }
