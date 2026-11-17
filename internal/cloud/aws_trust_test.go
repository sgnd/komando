package cloud

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/sgnd/komando/internal/transport"
)

// An AI agent's HTTPS_PROXY and AWS_CA_BUNDLE must not reach the AWS SDK
// client: with both it read secret values, SSO tokens and temporary keys.
func TestAWSIgnoresAnAgentsProxyAndCA(t *testing.T) {
	t.Cleanup(transport.DistrustEnv())
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent-mitm-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	f := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	t.Setenv("AWS_CA_BUNDLE", f)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAXXXX")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "x")
	t.Setenv("AWS_REGION", "us-east-1")
	cfg, err := AWSConfig(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	bc, ok := cfg.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("client %T", cfg.HTTPClient)
	}
	tr := bc.GetTransport()
	req, _ := http.NewRequest("GET", "https://secretsmanager.us-east-1.amazonaws.com/", nil)
	p, _ := tr.Proxy(req)
	agentCA := false
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
		c, _ := x509.ParseCertificate(der)
		_, verr := c.Verify(x509.VerifyOptions{Roots: tr.TLSClientConfig.RootCAs})
		agentCA = verr == nil
	}
	t.Logf("proxy=%v agentCAtrusted=%v", p, agentCA)
	if p != nil || agentCA {
		t.Errorf("the AWS SDK client takes the agent's proxy/CA")
	}
}
