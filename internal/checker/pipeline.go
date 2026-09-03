package checker

import (
	"context"
	"sync"
	"time"

	"reality-scanner/internal/model"
)

// Pipeline Reality 规则校验流水线
type Pipeline struct {
	timeout time.Duration
}

// NewPipeline 创建流水线
func NewPipeline(timeout time.Duration) *Pipeline {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Pipeline{timeout: timeout}
}

// Check 检验单个目标（支持透传原始 IP）
func (p *Pipeline) Check(ctx context.Context, domain string, targetIP string) *model.DetectionResult {
	start := time.Now()
	res := &model.DetectionResult{
		Domain:   domain,
		TargetIP: targetIP,
	}

	defer func() {
		res.Duration = time.Since(start)
	}()

	// 1. 被墙检测
	isBlocked, reason := GetBlockedDetector().IsBlocked(domain)
	if isBlocked {
		res.IsBlocked = true
		res.BlockedReason = reason
		res.EarlyExit = true
		EvaluateSuitability(res)
		return res
	}

	// 2. 地理位置检测
	country, isDomestic, _ := GetLocationDetector().CheckLocation(targetIP, domain)
	res.Country = country
	res.IsDomestic = isDomestic
	if isDomestic {
		res.EarlyExit = true
		EvaluateSuitability(res)
		return res
	}

	// 3. HTTP 重定向与状态码检测
	httpRes := CheckHTTP(ctx, domain, p.timeout)
	res.Accessible = httpRes.Accessible
	res.StatusCode = httpRes.StatusCode
	res.StatusCat = model.ClassifyStatusCode(httpRes.StatusCode, httpRes.Accessible)
	res.FinalDomain = httpRes.FinalDomain
	res.IsRedirected = httpRes.IsRedirected
	res.RedirectChain = httpRes.RedirectChain

	// 若存在重定向，使用重定向后的最终域名进行后续检测
	activeDomain := domain
	if httpRes.IsRedirected && httpRes.FinalDomain != "" {
		activeDomain = httpRes.FinalDomain
	}

	// 4. DNS 正向一致性交叉校验
	dnsRes := CheckDNSConsistency(ctx, activeDomain, targetIP, p.timeout)
	res.DNSMatchLevel = dnsRes.MatchLevel
	res.DNSMatchDesc = dnsRes.MatchDesc
	res.ResolvedIPs = dnsRes.ResolvedIPs

	if dnsRes.IsDead {
		res.EarlyExit = true
		EvaluateSuitability(res)
		return res
	}

	// 状态码如果异常，提前终止
	if !res.Accessible || res.StatusCat == model.StatusCodeCategoryExcluded {
		res.EarlyExit = true
		EvaluateSuitability(res)
		return res
	}

	// 4. 深度 TLS 握手检测 (TLS1.3 + H2 + SNI + 证书有效 + 强制X25519)
	tlsRes := CheckTLS(ctx, activeDomain, targetIP, p.timeout)
	res.SupportsTLS13 = tlsRes.SupportsTLS13
	res.SupportsX25519 = tlsRes.SupportsX25519
	res.SupportsHTTP2 = tlsRes.SupportsHTTP2
	res.HandshakeTime = tlsRes.HandshakeTime
	res.CipherSuite = tlsRes.CipherSuite

	res.CertValid = tlsRes.CertValid
	res.CertDaysUntilExpiry = tlsRes.CertDaysUntilExpiry
	res.CertIssuer = tlsRes.CertIssuer
	res.CertSubject = tlsRes.CertSubject
	res.SNIMatch = tlsRes.SNIMatch
	res.NotBefore = tlsRes.NotBefore
	res.NotAfter = tlsRes.NotAfter

	if !res.SupportsTLS13 || !res.SupportsHTTP2 || !res.SNIMatch {
		res.EarlyExit = true
		EvaluateSuitability(res)
		return res
	}

	// 5. 综合 CDN 识别
	isCDN, provider, confidence, evidence := GetCDNDetector().DetectCDN(activeDomain, httpRes.Headers, tlsRes.CertIssuer)
	res.IsCDN = isCDN
	res.CDNProvider = provider
	res.CDNConfidence = confidence
	res.CDNEvidence = evidence

	// 6. 热门网站降权检测
	res.IsHotWebsite = GetHotDetector().IsHotWebsite(activeDomain)

	// 7. 最终评估与星级判定
	EvaluateSuitability(res)
	return res
}

// CheckBatch 并发批量检验一组候选目标
func (p *Pipeline) CheckBatch(
	ctx context.Context,
	candidates []model.Candidate,
	threads int,
	onProgress func(done int, total int, res *model.DetectionResult),
) []*model.DetectionResult {
	if threads <= 0 {
		threads = 10
	}

	total := len(candidates)
	results := make([]*model.DetectionResult, total)
	if total == 0 {
		return results
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)
	var doneCount int
	var mu sync.Mutex

	for i, cand := range candidates {
		wg.Add(1)
		go func(idx int, c model.Candidate) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[idx] = &model.DetectionResult{
					Domain:   c.Domain,
					TargetIP: c.TargetIP,
					Error:    ctx.Err(),
				}
				return
			}

			// 执行流水线检测
			res := p.Check(ctx, c.Domain, c.TargetIP)
			results[idx] = res

			mu.Lock()
			doneCount++
			currentDone := doneCount
			mu.Unlock()

			if onProgress != nil {
				onProgress(currentDone, total, res)
			}
		}(i, cand)
	}

	wg.Wait()
	return results
}
