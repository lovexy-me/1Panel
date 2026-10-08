package service

import (
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
)

func TestNormalizeWafConfig(t *testing.T) {
	cfg := defaultWafConfig()
	cfg.IPBlack = []string{" 1.2.3.4 ", "10.0.0.0/8", "1.2.3.4", "", "::1"}
	cfg.MethodWhite = []string{"get", "POST"}
	out, err := normalizeWafConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.IPBlack) != 3 || out.MethodWhite[0] != "GET" || out.LogFile != wafContainerLog {
		t.Fatalf("unexpected %+v", out)
	}
	for _, bad := range []dto.WafConfig{
		{IPWhite: []string{"1.2.3.999"}},
		{IPWhite: []string{"::/0"}},
		{URLBlack: []string{"a\nb"}},
		{MethodWhite: []string{"HACK"}},
		{RealIPHeader: "X-Real-IP\r\nfoo"},
		{DisabledHosts: []string{"a.com;evil"}},
	} {
		if _, err := normalizeWafConfig(bad); err == nil {
			t.Fatalf("expected error for %+v", bad)
		}
	}
}

func TestDisableLegacyWaf(t *testing.T) {
	conf := "http {\n    include /usr/local/openresty/1pwaf/data/conf/waf.conf;\n    # include /usr/local/openresty/1pwaf/x;\n    include conf.d/*.conf;\n}\n"
	out, changed := disableLegacyWaf(conf)
	if !changed || !strings.Contains(out, "    # include /usr/local/openresty/1pwaf/data/conf/waf.conf; # disabled") {
		t.Fatalf("got %q", out)
	}
	if again, ch := disableLegacyWaf(out); ch || again != out {
		t.Fatal("not idempotent")
	}
}
