package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// EC2Instance is a running EC2 server, as import aws-ec2 adds it.
type EC2Instance struct {
	ID, Name, Region, Zone   string
	PublicIP, PublicDNS      string
	PrivateIP, PrivateDNS    string
	Platform, KeyName, VPCID string
}

// ec2Version is the EC2 Query API version komando speaks.
const ec2Version = "2016-11-15"

// EC2Instances lists the running instances of one region with the keys
// creds, by the EC2 Query API (DescribeInstances, read only), signed as
// the SDKs sign it. endpoint, when set, replaces ec2.REGION.amazonaws.com
// (a test server, LocalStack). It reads at most max instances.
func EC2Instances(ctx context.Context, creds aws.Credentials, region, endpoint string, max int) ([]EC2Instance, error) {
	base := strings.TrimSuffix(endpoint, "/")
	if base == "" {
		base = "https://ec2." + region + ".amazonaws.com"
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	signer := v4.NewSigner()
	var all []EC2Instance
	token := ""
	for len(all) < max {
		q := url.Values{"Action": {"DescribeInstances"}, "Version": {ec2Version}, "MaxResults": {"1000"},
			"Filter.1.Name": {"instance-state-name"}, "Filter.1.Value.1": {"running"}}
		if token != "" {
			q.Set("NextToken", token)
		}
		body := []byte(q.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		sum := sha256.Sum256(body)
		if err := signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "ec2", region, time.Now()); err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, ec2Err(resp.StatusCode, data)
		}
		page, next, err := parseDescribeInstances(data, region)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		token = next
	}
	if len(all) > max {
		all = all[:max]
	}
	return all, nil
}

// ec2Err is EC2's answer to a refused call: "UnauthorizedOperation: ...".
func ec2Err(status int, data []byte) error {
	var e struct {
		Errors []struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Errors>Error"`
	}
	if xml.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
		return fmt.Errorf("EC2: %s: %s", e.Errors[0].Code, e.Errors[0].Message)
	}
	return fmt.Errorf("EC2 answered %d", status)
}

// parseDescribeInstances reads one DescribeInstances answer.
func parseDescribeInstances(data []byte, region string) ([]EC2Instance, string, error) {
	var r struct {
		Reservations []struct {
			Instances []struct {
				ID         string `xml:"instanceId"`
				PrivateIP  string `xml:"privateIpAddress"`
				PublicIP   string `xml:"ipAddress"`
				PublicDNS  string `xml:"dnsName"`
				PrivateDNS string `xml:"privateDnsName"`
				Platform   string `xml:"platform"`
				KeyName    string `xml:"keyName"`
				VPCID      string `xml:"vpcId"`
				Zone       string `xml:"placement>availabilityZone"`
				Tags       []struct {
					Key   string `xml:"key"`
					Value string `xml:"value"`
				} `xml:"tagSet>item"`
			} `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
		NextToken string `xml:"nextToken"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, "", fmt.Errorf("the answer is not EC2's (is the endpoint EC2?): %w", err)
	}
	var out []EC2Instance
	for _, res := range r.Reservations {
		for _, i := range res.Instances {
			in := EC2Instance{ID: i.ID, Region: region, Zone: i.Zone, PublicIP: i.PublicIP, PublicDNS: i.PublicDNS,
				PrivateIP: i.PrivateIP, PrivateDNS: i.PrivateDNS, Platform: i.Platform, KeyName: i.KeyName, VPCID: i.VPCID}
			for _, t := range i.Tags {
				if t.Key == "Name" {
					in.Name = t.Value
				}
			}
			out = append(out, in)
		}
	}
	return out, r.NextToken, nil
}
