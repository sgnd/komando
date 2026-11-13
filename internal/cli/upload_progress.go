package cli

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// --progress: with -o json, upload, download, cp, sync and storage
// upload/download write how far they are to stderr, one JSON object per
// line (NDJSON), at most about 4 a second, then one "done" line. The
// stdout envelope stays as it is. A program (the Mac app, an agent) draws
// a progress bar from it; it holds paths and counts, never file contents.
//
//	{"event":"progress","file":"db.sql.gz","bytes_done":1048576,"bytes_total":4194304,"files_done":0,"files_total":1}
//	{"event":"done","file":"db.sql.gz","bytes_done":4194304,"bytes_total":4194304,"files_done":1,"files_total":1,"ok":true}

const progressUsage = "with -o json, write progress to the error output (stderr), one JSON object per line"

// progressEvery is the shortest time between two progress lines.
const progressEvery = 250 * time.Millisecond

// progressClock is the clock progress lines are timed by (a variable so
// tests can move it).
var progressClock = time.Now

// progressEvent is one NDJSON line. A total is null while it is not
// known (a folder download from a server lists nothing first).
type progressEvent struct {
	Event      string `json:"event"` // progress, done
	File       string `json:"file"`  // the file being moved; inside a folder, its path in the folder
	BytesDone  int64  `json:"bytes_done"`
	BytesTotal *int64 `json:"bytes_total"`
	FilesDone  int    `json:"files_done"`
	FilesTotal *int   `json:"files_total"`
	OK         *bool  `json:"ok,omitempty"` // done only: whether the command ended without an error
}

// xferProgress counts one command's transfer: every server and file in it.
type xferProgress struct {
	cl       *call // the call it works for
	mu       sync.Mutex
	w        io.Writer
	last     time.Time
	sent     bool
	file     string
	bytes    int64
	files    int
	totBytes int64
	totFiles int
	parts    int  // how many totals make the whole one known
	got      int  // totals given so far
	noTotal  bool // a part cannot know its total
	finished bool
}

// progressPart is the share of one server (or of the whole command when
// it has one side): it gives its total once. A nil part does nothing, so
// code without --progress calls it freely.
type progressPart struct {
	p    *xferProgress
	once sync.Once
}

type progressKey struct{}

// progressFrom is the part ctx carries, or nil.
func progressFrom(ctx context.Context) *progressPart {
	pp, _ := ctx.Value(progressKey{}).(*progressPart)
	return pp
}

// startProgress turns --progress on for one command run: with -o json and
// a real run, the returned ctx carries it and finish writes the done line.
// Otherwise ctx is returned as it is and nothing is written.
func startProgress(cl *call, ctx context.Context, on bool) (context.Context, func(error) error) {
	if !on || cl.out.Format == "text" || cl.flags.dryRun {
		return ctx, func(err error) error { return err }
	}
	ctx, p := withProgress(cl, ctx, cl.out.Err)
	return ctx, func(err error) error {
		p.done(err == nil)
		return err
	}
}

// withProgress is ctx carrying a new progress count, written to w.
func withProgress(cl *call, ctx context.Context, w io.Writer) (context.Context, *xferProgress) {
	p := &xferProgress{cl: cl, w: w, parts: 1}
	return context.WithValue(ctx, progressKey{}, &progressPart{p: p}), p
}

// eachServer says the totals come from n servers, one part each
// (progressServer); before, the command was one part.
func (pp *progressPart) eachServer(n int) {
	if pp == nil {
		return
	}
	pp.p.mu.Lock()
	pp.p.parts = n
	pp.p.mu.Unlock()
}

// progressServer gives one server's work its own part. settle counts a
// server that ended before it knew its total (it could not connect) as
// moving nothing, so the others' totals still show.
func progressServer(ctx context.Context) (context.Context, func()) {
	pp := progressFrom(ctx)
	if pp == nil {
		return ctx, func() {}
	}
	own := &progressPart{p: pp.p}
	return context.WithValue(ctx, progressKey{}, own), func() { own.total(0, 0) }
}

// total is this part's files and bytes; only the first call counts.
func (pp *progressPart) total(files int, bytes int64) {
	if pp == nil {
		return
	}
	pp.once.Do(func() {
		p := pp.p
		p.mu.Lock()
		p.got++
		p.totFiles += files
		p.totBytes += bytes
		p.mu.Unlock()
	})
}

// unknown says this part cannot know its total: the totals stay null.
func (pp *progressPart) unknown() {
	if pp == nil {
		return
	}
	pp.once.Do(func() {
		p := pp.p
		p.mu.Lock()
		p.got++
		p.noTotal = true
		p.mu.Unlock()
	})
}

// start names the file being moved now.
func (pp *progressPart) start(file string) {
	if pp == nil {
		return
	}
	p := pp.p
	p.mu.Lock()
	defer p.mu.Unlock()
	p.file = file
	p.tick()
}

// fileDone counts one file moved in full.
func (pp *progressPart) fileDone() {
	if pp == nil {
		return
	}
	p := pp.p
	p.mu.Lock()
	defer p.mu.Unlock()
	p.files++
	p.tick()
}

func (p *xferProgress) add(n int64) {
	if n == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytes += n
	p.tick()
}

// reader counts what is read from r. A reader that can seek still can
// (an FTP upload starts over after a reconnect): the count follows it.
func (pp *progressPart) reader(r io.Reader) io.Reader {
	if pp == nil {
		return r
	}
	c := &countReader{r: r, p: pp.p}
	if s, ok := r.(io.Seeker); ok {
		return &countReadSeeker{countReader: c, s: s}
	}
	return c
}

// writer counts what is written to it (to go beside the real writer).
func (pp *progressPart) writer() io.Writer {
	if pp == nil {
		return nil
	}
	return &countReader{p: pp.p}
}

type countReader struct {
	r   io.Reader
	p   *xferProgress
	pos int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.pos += int64(n)
	c.p.add(int64(n))
	return n, err
}

func (c *countReader) Write(b []byte) (int, error) {
	c.p.add(int64(len(b)))
	return len(b), nil
}

type countReadSeeker struct {
	*countReader
	s io.Seeker
}

func (c *countReadSeeker) Seek(off int64, whence int) (int64, error) {
	n, err := c.s.Seek(off, whence)
	if err == nil {
		c.p.add(n - c.pos)
		c.pos = n
	}
	return n, err
}

// tick writes a progress line unless one went out less than progressEvery
// ago. The caller holds mu.
func (p *xferProgress) tick() {
	if p.sent && progressClock().Sub(p.last) < progressEvery {
		return
	}
	p.write("progress", nil)
}

// done writes the last line, once, whatever the throttle says.
func (p *xferProgress) done(ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.finished = true
	p.write("done", &ok)
}

func (p *xferProgress) write(event string, ok *bool) {
	if p.finished && event != "done" {
		return
	}
	e := progressEvent{Event: event, File: p.file, BytesDone: p.bytes, FilesDone: p.files, OK: ok}
	e.File = p.cl.out.Redact(e.File) // a name never shows a secret value
	if !p.noTotal && p.got >= p.parts {
		b, f := p.totBytes, p.totFiles
		e.BytesTotal, e.FilesTotal = &b, &f
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = p.w.Write(append(line, '\n'))
	p.sent, p.last = true, progressClock()
}
