package cli

import (
	"context"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/registry"
)

// The tags of a repository: what prune reads of each, and which tags
// registry rm takes with an image.

// pruneTags reads each tag's digest, and the build date of each image a
// tag of the rule may take.
func pruneTags(ctx context.Context, r *registry.Client, repo string, rule registry.PruneRule) ([]registry.TagInfo, error) {
	tags, err := r.Tags(ctx, repo, maxRepoTags+1)
	if err != nil {
		return nil, imageErr(ctx, r, repo, "", err)
	}
	if len(tags) > maxRepoTags {
		return nil, out.Errf(out.ExitUsage, "TOO_MANY_TAGS", "komando prunes a repository of at most 10000 tags, and --match does not change that (every tag is read, so a kept tag protects its image): delete some first with `komando registry rm CONN IMAGE`",
			"%s has more than %d tags", repo, maxRepoTags)
	}
	// a HEAD per tag for its digest (several at once), then one read per
	// image: tags often share images, and Docker Hub counts every
	// manifest read as a pull
	digests, err := tagDigests(ctx, r, repo, tags)
	if err != nil {
		return nil, err
	}
	infos := make([]registry.TagInfo, 0, len(tags))
	built := map[string]time.Time{}
	for i, t := range tags {
		d := digests[i]
		if d == "" { // the registry did not say: read the manifest
			m, err := r.Inspect(ctx, repo, t)
			if err != nil {
				return nil, err
			}
			d = m.Digest
		}
		// only an image a tag may go with needs its build date
		cand := t != "latest" && (rule.Match == nil || rule.Match.MatchString(t))
		if _, ok := built[d]; !ok && d != "" && cand {
			m, err := r.Inspect(ctx, repo, d)
			if err != nil {
				return nil, err
			}
			ts, _ := time.Parse(time.RFC3339Nano, m.Created)
			built[d] = ts
		}
		infos = append(infos, registry.TagInfo{Tag: t, Digest: d, Created: built[d]})
	}
	return infos, nil
}

// maxRepoTags is the most tags komando reads of one repository (prune,
// and what rm says it takes): a HEAD request each.
const maxRepoTags = 10000

// tagLookups is how many tag digests are asked for at once.
const tagLookups = 8

// tagDigests is the digest of each tag of repo (HEAD requests, which
// Docker Hub does not count as pulls), several at once, in tags' order.
// A tag whose registry gives no digest has "".
func tagDigests(ctx context.Context, r *registry.Client, repo string, tags []string) ([]string, error) {
	digests := make([]string, len(tags))
	errs := make([]error, len(tags))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(tagLookups, len(tags)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				digests[i], errs[i] = r.Digest(ctx, repo, tags[i])
			}
		}()
	}
	for i := range tags {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return digests, nil
}

// tagsOn lists the tags of repo that point at digest, reading every tag
// up to maxRepoTags. more is true when the repo has more tags than that.
func tagsOn(ctx context.Context, r *registry.Client, repo, digest string) (tags []string, checked int, more bool) {
	all, err := r.Tags(ctx, repo, maxRepoTags+1)
	if err != nil {
		return nil, 0, false
	}
	if len(all) > maxRepoTags {
		all, more = all[:maxRepoTags], true
	}
	tags = []string{}
	digests := make([]string, len(all))
	if ds, err := tagDigests(ctx, r, repo, all); err == nil {
		digests = ds
	} else {
		for i, t := range all { // one failed: ask one by one, keep what answers
			digests[i], _ = r.Digest(ctx, repo, t)
		}
	}
	for i, t := range all {
		if digests[i] == digest {
			tags = append(tags, t)
		}
	}
	return tags, len(all), more
}
