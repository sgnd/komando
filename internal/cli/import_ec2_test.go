package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ec2Page1 = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<reservationSet><item><instancesSet>
<item><instanceId>i-0aaa</instanceId><privateIpAddress>10.0.1.5</privateIpAddress><ipAddress>203.0.113.5</ipAddress>
<dnsName>ec2-203-0-113-5.eu-west-1.compute.amazonaws.com</dnsName><keyName>deploy-key</keyName>
<placement><availabilityZone>eu-west-1a</availabilityZone></placement>
<tagSet><item><key>Name</key><value>web 1</value></item><item><key>env</key><value>prod</value></item></tagSet></item>
</instancesSet></item></reservationSet><nextToken>page2</nextToken></DescribeInstancesResponse>`

const ec2Page2 = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<reservationSet><item><instancesSet>
<item><instanceId>i-0bbb</instanceId><privateIpAddress>10.0.2.9</privateIpAddress><platform>windows</platform>
<placement><availabilityZone>eu-west-1b</availabilityZone></placement></item>
</instancesSet></item></reservationSet></DescribeInstancesResponse>`

// import aws-ec2 reads each profile's running instances (signed for ec2
// in the profile's region, two pages) and adds a server for each: named
// by its Name tag or ID, grouped by region, labelled with its ID; one with
// no public address and a Windows one are listed with what to do.
func TestImportAWSEC2(t *testing.T) {
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(b))
		auths = append(auths, r.Header.Get("Authorization"))
		if q.Get("Action") != "DescribeInstances" || q.Get("Filter.1.Value.1") != "running" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		if q.Get("NextToken") == "page2" {
			io.WriteString(w, ec2Page2)
			return
		}
		io.WriteString(w, ec2Page1)
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("[profile shop]\nregion = eu-west-1\nendpoint_url = "+srv.URL+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "credentials"), []byte("[shop]\naws_access_key_id = AKIATEST\naws_secret_access_key = s\n"), 0o600)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	p, err := importAWSEC2(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) != 2 || !strings.Contains(auths[0], "/eu-west-1/ec2/aws4_request") {
		t.Fatalf("requests %q", auths)
	}
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts %+v notes %v", p.Hosts, p.Notes)
	}
	web, win := p.Hosts[0], p.Hosts[1]
	if web.Name != "web-1" || web.Address != "ec2-203-0-113-5.eu-west-1.compute.amazonaws.com" || web.Groups[0] != "eu-west-1" || web.Labels["aws-instance"] != "i-0aaa" {
		t.Errorf("web %+v", web)
	}
	if win.Name != "i-0bbb" || win.Address != "10.0.2.9" || win.OS != "windows" {
		t.Errorf("win %+v", win)
	}
	notes := strings.Join(p.Notes, "\n")
	for _, want := range []string{"deploy-key", "no public address", "--via BASTION", "Windows server"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}
