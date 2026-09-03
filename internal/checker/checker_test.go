package checker

import (
	"context"
	"testing"
	"time"
)

func TestGFWListDetector(t *testing.T) {
	d := GetBlockedDetector()
	blocked, _ := d.IsBlocked("google.com")
	if !blocked {
		t.Errorf("expected google.com to be blocked")
	}

	blocked2, _ := d.IsBlocked("example.com")
	if blocked2 {
		t.Errorf("expected example.com not to be blocked")
	}
}

func TestHotDetector(t *testing.T) {
	d := GetHotDetector()
	if !d.IsHotWebsite("apple.com") {
		t.Errorf("expected apple.com to be a hot website")
	}
	if !d.IsHotWebsite("www.apple.com") {
		t.Errorf("expected www.apple.com to be a hot website")
	}
	if d.IsHotWebsite("unknown-small-test-site.xyz") {
		t.Errorf("expected small site not to be a hot website")
	}
}

func TestGeoIPDetector(t *testing.T) {
	d := GetLocationDetector()
	// 114.114.114.114 is in China
	country, isDomestic, err := d.CheckLocation("114.114.114.114", "")
	if err != nil {
		t.Fatalf("CheckLocation failed: %v", err)
	}
	if !isDomestic {
		t.Errorf("expected 114.114.114.114 to be domestic, got %s, %v", country, isDomestic)
	}

	// 1.1.1.1 is Cloudflare (Australia/US)
	country2, isDomestic2, err := d.CheckLocation("1.1.1.1", "")
	if err != nil {
		t.Fatalf("CheckLocation failed: %v", err)
	}
	if isDomestic2 {
		t.Errorf("expected 1.1.1.1 not to be domestic, got %s", country2)
	}
}

func TestCheckDNSConsistency(t *testing.T) {
	ctx := context.Background()

	// 1. 测试伯克利镜像站 (真实公网解析为 169.229.200.70)
	res := CheckDNSConsistency(ctx, "apt.ocf.berkeley.edu", "169.229.200.70", 3*time.Second)
	if res.MatchLevel != "direct" {
		t.Errorf("expected direct match for 169.229.200.70, got %s (%s)", res.MatchLevel, res.MatchDesc)
	}

	// 2. 测试同 C 段邻近 IP (例如 169.229.200.100)
	resSubnet := CheckDNSConsistency(ctx, "apt.ocf.berkeley.edu", "169.229.200.100", 3*time.Second)
	if resSubnet.MatchLevel != "subnet" {
		t.Errorf("expected subnet match for 169.229.200.100, got %s (%s)", resSubnet.MatchLevel, resSubnet.MatchDesc)
	}

	// 3. 测试跨网段 IP (例如 103.103.245.100)
	resRemote := CheckDNSConsistency(ctx, "apt.ocf.berkeley.edu", "103.103.245.100", 3*time.Second)
	if resRemote.MatchLevel != "remote" {
		t.Errorf("expected remote match for 103.103.245.100, got %s (%s)", resRemote.MatchLevel, resRemote.MatchDesc)
	}
}
