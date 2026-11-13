package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/store"
)

// ec2ImportMax is the most instances import aws-ec2 reads per profile.
const ec2ImportMax = 5000

// importAWSEC2 adds a server per running EC2 instance of each profile in
// ~/.aws/config, in the profile's region, read with the profile's own
// login (SSO and roles included; nothing is written to AWS). A server is
// named by its Name tag (else its instance ID), put in a group named
// after the region, and labelled with its instance ID. An instance with
// no public address, or a Windows one, is listed with what to do.
func importAWSEC2(cl *call, path string) (*importPlan, error) {
	profiles, credsFile, err := awsImportProfiles(cl, path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	if len(profiles) == 0 {
		p.Notes = append(p.Notes, path+": no AWS profiles")
		return p, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, prof := range profiles {
		creds, region, endpoint, ok := awsImportAccess(ctx, p, prof, path, credsFile)
		if !ok {
			continue
		}
		if region == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("profile %s: no region (set region = ... under it in %s), so its servers are not read", prof, path))
			continue
		}
		list, err := cloud.EC2Instances(ctx, creds, region, endpoint, ec2ImportMax)
		if err != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("profile %s: cannot list its EC2 servers in %s: %v", prof, region, err))
			continue
		}
		if len(list) == 0 {
			p.Notes = append(p.Notes, fmt.Sprintf("profile %s: no running EC2 servers in %s", prof, region))
		}
		for _, in := range list {
			p.Hosts = append(p.Hosts, ec2Host(p, prof, in))
		}
	}
	return p, nil
}

// ec2Host is the server for one instance.
func ec2Host(p *importPlan, prof string, in cloud.EC2Instance) *store.Host {
	name := p.name(in.Name)
	if in.Name == "" {
		name = p.name(in.ID)
	}
	addr := in.PublicDNS
	switch {
	case addr == "" && in.PublicIP != "":
		addr = in.PublicIP
	case addr == "":
		addr = in.PrivateIP
		p.Notes = append(p.Notes, fmt.Sprintf("%s: no public address, only %s; reach it through a server in its network (`komando host edit %s --via BASTION`) or AWS Session Manager (`--ssm`)", name, in.PrivateIP, name))
	}
	h := &store.Host{Name: name, Address: addr, Groups: []string{in.Region},
		Labels: map[string]string{"aws-instance": in.ID, "aws-profile": prof}}
	if in.Platform == "windows" {
		h.OS = "windows"
		p.Notes = append(p.Notes, name+": a Windows server; komando reaches it over OpenSSH or WinRM (see the Windows guide)")
	}
	if in.KeyName != "" {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: launched with the EC2 key pair %q; add its key (`komando key add NAME FILE`) and `komando host edit %s --key NAME`, and set the login user (ec2-user, ubuntu, admin ...) with --user", name, in.KeyName, name))
	}
	return h
}
