package checker

import (
	"context"
	"testing"
	"time"

	"reality-scanner/internal/model"
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

func TestEvaluateSuitabilityWeighted(t *testing.T) {
	// 1. 黄金满分目标 (100分 -> 5星)
	perfect := &model.DetectionResult{
		Accessible:          true,
		StatusCode:          200,
		StatusCat:           model.StatusCodeCategorySafe,
		SupportsTLS13:       true,
		SupportsX25519:      true,
		SupportsHTTP2:       true,
		SNIMatch:            true,
		CertValid:           true,
		CertDaysUntilExpiry: 80,
		HandshakeTime:       40 * time.Millisecond,
		IsCDN:               false,
		IsHotWebsite:        false,
		IsBlocked:           false,
		IsDomestic:          false,
		DNSMatchLevel:       "direct",
	}
	EvaluateSuitability(perfect)
	if !perfect.Suitable || perfect.Score != 100.0 || perfect.Stars != 5 {
		t.Errorf("expected perfect score 100.0 with 5 stars, got %.1f score, %d stars", perfect.Score, perfect.Stars)
	}

	// 2. 优质 4 星目标 (DNS同C段 22 + 无CDN 25 + 延迟 80ms 17 + 非热门 15 + 证书 45天 5 = 84分)
	good := &model.DetectionResult{
		Accessible:          true,
		StatusCode:          200,
		StatusCat:           model.StatusCodeCategorySafe,
		SupportsTLS13:       true,
		SupportsX25519:      true,
		SupportsHTTP2:       true,
		SNIMatch:            true,
		CertValid:           true,
		CertDaysUntilExpiry: 45,
		HandshakeTime:       80 * time.Millisecond,
		IsCDN:               false,
		IsHotWebsite:        false,
		IsBlocked:           false,
		IsDomestic:          false,
		DNSMatchLevel:       "subnet",
	}
	EvaluateSuitability(good)
	if !good.Suitable || good.Score != 84.0 || good.Stars != 4 {
		t.Errorf("expected score 84.0 with 4 stars, got %.1f score, %d stars", good.Score, good.Stars)
	}

	// 3. 一票否决目标 (不支持 TLS 1.3 -> 0分 / 不适合)
	bad := &model.DetectionResult{
		Accessible:     true,
		StatusCode:     200,
		StatusCat:      model.StatusCodeCategorySafe,
		SupportsTLS13:  false, // 致命伤
		SupportsX25519: true,
		SupportsHTTP2:  true,
		SNIMatch:       true,
		CertValid:      true,
	}
	EvaluateSuitability(bad)
	if bad.Suitable || bad.Score != 0.0 || bad.Stars != 0 {
		t.Errorf("expected bad target to be unsuitable with 0 stars and 0 score, got suitable=%v, score=%.1f, stars=%d", bad.Suitable, bad.Score, bad.Stars)
	}

	// 4. 排序测试 (高分优先)
	list := []*model.DetectionResult{good, perfect}
	SortResultsByStars(list)
	if list[0] != perfect || list[1] != good {
		t.Errorf("expected perfect (100.0) before good (84.0)")
	}
}
