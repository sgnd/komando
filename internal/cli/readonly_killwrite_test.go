package cli

import "testing"

// Read tools on the allowlist that write a file or kill with one flag or
// form: that form breaks --read-only (both lists), the plain read does not.
func TestReadOnlyToolWriteForms(t *testing.T) {
	refused := []string{
		"xxd /etc/hosts /tmp/out", "xxd -r dump.hex /usr/local/bin/x", "xxd -c 16 in out", "xxd -s 0x10 -l 32 in out",
		"xxd -cols 8 in out",
		"yq -i '.a = 1' f.yaml", "yq --inplace '.a=1' f.yaml", "yq --in-place .a f.yaml", "yq -Pi '.a=1' f.yaml",
		"yq -s '.name' f.yaml", "yq --split-exp .name f.yaml", "yq -i=true .a f.yaml",
		"xmllint --output /etc/x f.xml", "xmllint --output=/etc/x f.xml", "xmllint -o /etc/x f.xml", "xmllint --shell f.xml",
		"fuser -k 80/tcp", "fuser -km /data", "fuser --kill /data", "fuser -v -k -9 /data",
		"ss -K dst 10.0.0.1", "ss --kill dport = 22", "ss -tK", "ss -D /tmp/dump", "ss --diag=/tmp/dump",
		"arp -d 10.0.0.1", "arp --delete 10.0.0.1", "arp -s 10.0.0.1 aa:bb:cc:dd:ee:ff", "arp --set 10.0.0.1 x",
		"arp -f /etc/ethers", "arp --file /etc/ethers", "arp -nd 10.0.0.1",
		"sar -o /tmp/sa 1 3", "sar -o", "sar -uo /tmp/sa 1 1", "sar -o/tmp/sa 1 1",
	}
	for _, c := range refused {
		if w := readOnlyViolation(c); w == "" {
			t.Errorf("%q: --read-only let it through (denylist)", c)
		}
		if w := readOnlyAllowlist(c); w == "" {
			t.Errorf("%q: --read-only let it through (allowlist)", c)
		}
	}
	allowed := []string{
		"xxd /etc/hosts", "xxd -l 64 /bin/ls", "xxd -r dump.hex", "xxd in -", "xxd -c 16 -g 1 in", "xxd",
		"yq '.a' f.yaml", "yq -P '.a' f.yaml", "yq -o json '.' f.yaml", "yq e '.a' f.yaml",
		"xmllint --format f.xml", "xmllint --noout --schema s.xsd f.xml", "xmllint --xpath '//a' f.xml",
		"fuser -v /data", "fuser -m /data", "fuser -n tcp 80",
		"ss -tlnp", "ss -s", "ss -tan state established",
		"arp -n", "arp -a", "arp -i eth0 -n",
		"sar -u 1 3", "sar -f /var/log/sa/sa01", "sar -n DEV 1 1",
	}
	for _, c := range allowed {
		if w := readOnlyAllowlist(c); w != "" {
			t.Errorf("%q: refused (%s), a plain read", c, w)
		}
	}
}
