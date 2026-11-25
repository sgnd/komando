package term

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// SignalContext is cancelled by the first Ctrl-C (or SIGTERM, or SIGHUP:
// the terminal closed), so the command stops cleanly. A second one calls
// onSecond with that signal, which ends the process at once, as with
// kubectl and gh, when the clean stop hangs. A nil onSecond still ends it:
// the process dies of the signal (exit 130 where a signal cannot end it).
// A SIGHUP that was ignored when the process started (nohup, a background
// holder) stays ignored.
func SignalContext(parent context.Context, onSecond func(os.Signal)) (context.Context, context.CancelFunc) {
	if onSecond == nil {
		onSecond = endOnSignal
	}
	ctx, cancel := context.WithCancel(parent)
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			cancel()
		case <-done:
			return
		}
		select {
		case s := <-ch:
			onSecond(s)
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			cancel()
			signal.Stop(ch)
			close(done)
		})
	}
}

// endOnSignal ends the process on s: it dies of s, so a shell that runs it
// (a loop) sees the Ctrl-C too.
func endOnSignal(s os.Signal) {
	signal.Reset(s)
	Raise(s)
	os.Exit(130) // where a signal cannot end the process (Windows)
}
