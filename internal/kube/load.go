package kube

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Load reads kubeconfig files the way kubectl reads a KUBECONFIG list:
// the first file that names a context, cluster or user wins, and so does
// the first current-context. Relative file paths in a file (a minikube or
// kind certificate) count from that file's folder, not the current one.
// read reads one file; "-" is stdin and keeps paths as they are.
func Load(read func(path string) ([]byte, error), paths ...string) (*Config, error) {
	all := &Config{}
	for _, p := range paths {
		b, err := read(p)
		if err != nil {
			return nil, err
		}
		c, err := parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if p != "-" {
			if abs, err := filepath.Abs(p); err == nil {
				c.absPaths(filepath.Dir(abs))
			}
		}
		all.merge(c)
	}
	if len(all.Contexts) == 0 {
		return nil, fmt.Errorf("the kubeconfig has no contexts")
	}
	return all, nil
}

// absPaths makes the relative file paths in c count from dir.
func (c *Config) absPaths(dir string) {
	fix := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) && !strings.HasPrefix(*p, "~/") {
			*p = filepath.Join(dir, *p)
		}
	}
	for i := range c.Clusters {
		fix(&c.Clusters[i].Cluster.CertificateAuthority)
	}
	for i := range c.Users {
		u := &c.Users[i].User
		fix(&u.ClientCertificate)
		fix(&u.ClientKey)
		fix(&u.TokenFile)
	}
}

// merge adds what o names and c does not yet.
func (c *Config) merge(o *Config) {
	if c.CurrentContext == "" {
		c.CurrentContext = o.CurrentContext
	}
	for _, x := range o.Clusters {
		if !slices.ContainsFunc(c.Clusters, func(y NamedCluster) bool { return y.Name == x.Name }) {
			c.Clusters = append(c.Clusters, x)
		}
	}
	for _, x := range o.Users {
		if !slices.ContainsFunc(c.Users, func(y NamedUser) bool { return y.Name == x.Name }) {
			c.Users = append(c.Users, x)
		}
	}
	for _, x := range o.Contexts {
		if !slices.ContainsFunc(c.Contexts, func(y NamedContext) bool { return y.Name == x.Name }) {
			c.Contexts = append(c.Contexts, x)
		}
	}
}
