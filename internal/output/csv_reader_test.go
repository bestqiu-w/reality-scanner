package output

import (
	"strings"
	"testing"
)

func TestParseCSV_New11Cols(t *testing.T) {
	csvData := `IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
103.103.245.172,103.103.245.172,TLS 1.3,h2,X25519,2500,SHA256,RSA,voll.996969.xyz,"Let's Encrypt",HK
103.103.245.191,103.103.245.191,TLS 1.3,h2,X25519,2600,SHA256,RSA,hk.zpsonic.xyz,"Let's Encrypt",HK
`
	candidates, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("ParseCSV failed: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}

	if candidates[0].Domain != "voll.996969.xyz" {
		t.Errorf("expected domain voll.996969.xyz, got %s", candidates[0].Domain)
	}
	if candidates[0].TargetIP != "103.103.245.172" {
		t.Errorf("expected IP 103.103.245.172, got %s", candidates[0].TargetIP)
	}

	if candidates[1].Domain != "hk.zpsonic.xyz" {
		t.Errorf("expected domain hk.zpsonic.xyz, got %s", candidates[1].Domain)
	}
}

func TestParseCSV_Old5Cols(t *testing.T) {
	csvData := `IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
103.103.245.124,103.103.245.124,cwangrz.top,"Let's Encrypt",HK
103.103.245.175,103.103.245.175,20291010.xyz,"Let's Encrypt",HK
`
	candidates, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("ParseCSV failed: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}

	if candidates[0].Domain != "cwangrz.top" {
		t.Errorf("expected domain cwangrz.top, got %s", candidates[0].Domain)
	}
	if candidates[1].Domain != "20291010.xyz" {
		t.Errorf("expected domain 20291010.xyz, got %s", candidates[1].Domain)
	}
}
