package registry

import (
	"regexp"
	"sort"
	"time"
)

// TagInfo is one tag with the image it points at and when that was built.
type TagInfo struct {
	Tag     string
	Digest  string
	Created time.Time // zero: unknown (an index without one config)
}

// PruneRule says which tags may go: the newest Keep of the matching tags
// stay, and with OlderThan set only tags built before it go. "latest" and
// tags with no build date always stay.
type PruneRule struct {
	Keep      int
	OlderThan time.Time
	Match     *regexp.Regexp // nil: every tag
}

// PrunePlan is what a prune would do.
type PrunePlan struct {
	Delete []PruneImage `json:"delete"`
	Keep   []PruneKeep  `json:"keep"`
}

// PruneImage is one image (digest) to delete, with every tag on it.
type PruneImage struct {
	Digest  string    `json:"digest"`
	Tags    []string  `json:"tags"`
	Created time.Time `json:"created"`
}

// PruneKeep is a tag that stays, and why.
type PruneKeep struct {
	Tag    string `json:"tag"`
	Reason string `json:"reason"`
}

// Plan decides what to delete. Deleting by digest removes every tag on that
// image, so an image any kept tag points at is never deleted.
func (r PruneRule) Plan(tags []TagInfo) PrunePlan {
	var cands []TagInfo
	keep := map[string]string{} // tag -> reason
	for _, t := range tags {
		switch {
		case t.Tag == "latest":
			keep[t.Tag] = "latest is always kept"
		case r.Match != nil && !r.Match.MatchString(t.Tag):
			keep[t.Tag] = "does not match"
		case t.Created.IsZero() || t.Digest == "":
			keep[t.Tag] = "no build date"
		default:
			cands = append(cands, t)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Created.After(cands[j].Created) })
	var gone []TagInfo
	for i, t := range cands {
		switch {
		case i < r.Keep:
			keep[t.Tag] = "one of the newest"
		case !r.OlderThan.IsZero() && !t.Created.Before(r.OlderThan):
			keep[t.Tag] = "newer than the cutoff"
		default:
			gone = append(gone, t)
		}
	}
	// an image a kept tag points at stays, with all its tags
	keptDigest := map[string]string{}
	for _, t := range tags {
		if _, ok := keep[t.Tag]; ok && t.Digest != "" {
			keptDigest[t.Digest] = t.Tag
		}
	}
	var plan PrunePlan
	byDigest := map[string]*PruneImage{}
	for _, t := range gone {
		if other, ok := keptDigest[t.Digest]; ok {
			keep[t.Tag] = "same image as the kept tag " + other
			continue
		}
		img := byDigest[t.Digest]
		if img == nil {
			img = &PruneImage{Digest: t.Digest, Created: t.Created}
			byDigest[t.Digest] = img
		}
		img.Tags = append(img.Tags, t.Tag)
	}
	for _, t := range gone { // newest first, as sorted
		if img := byDigest[t.Digest]; img != nil {
			plan.Delete = append(plan.Delete, *img)
			delete(byDigest, t.Digest)
		}
	}
	for _, t := range tags {
		if why, ok := keep[t.Tag]; ok {
			plan.Keep = append(plan.Keep, PruneKeep{Tag: t.Tag, Reason: why})
		}
	}
	return plan
}
