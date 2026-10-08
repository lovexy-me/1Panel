package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/1Panel-dev/1Panel/agent/cmd/server/cwaf"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
)

const (
	wafHTTPConfName   = "1panel-cwaf.conf"
	wafLogMaxBytes    = 50 << 20
	wafLogReadBytes   = 8 << 20
	wafContainerLog   = "/www/cwaf/cwaf.log"
	wafMaxListEntries = 5000
)

var (
	wafMu sync.Mutex
	// matches active (non-comment) lines that load the bundled closed-source 1pwaf,
	// which would collide with our access_by_lua / lua_package_path directives.
	legacyWafLineRe = regexp.MustCompile(`(?m)^([ \t]*)([^#\s][^\n]*1pwaf/[^\n]*)$`)
	wafHostRe       = regexp.MustCompile(`^[A-Za-z0-9*.\-:\[\]]{1,253}$`)
	wafHeaderRe     = regexp.MustCompile(`^[A-Za-z0-9\-]{0,64}$`)
	wafMethods      = map[string]bool{"GET": true, "POST": true, "HEAD": true, "PUT": true, "DELETE": true, "OPTIONS": true, "PATCH": true, "PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true, "UNLOCK": true, "TRACE": true, "CONNECT": true}
)

type WafService struct{}

type IWafService interface {
	GetStatus() (dto.WafStatus, error)
	Update(req dto.WafConfig) error
	SearchLogs(req dto.WafLogSearch) (int64, []dto.WafLog, error)
	ClearLogs() error
	AddIP(req dto.WafIPReq) error
}

func NewIWafService() IWafService {
	return &WafService{}
}

func defaultWafConfig() dto.WafConfig {
	return dto.WafConfig{
		Enabled:       false,
		Mode:          "block",
		IPWhite:       []string{},
		IPBlack:       []string{},
		URLWhite:      []string{},
		URLBlack:      []string{},
		UABlack:       []string{},
		MethodWhite:   []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"},
		DisabledHosts: []string{},
		CC:            dto.WafCCConfig{Enabled: true, Requests: 300, Window: 60, BlockSeconds: 600},
		Sqli:          true,
		Xss:           true,
		Traversal:     true,
		Rce:           true,
		Scanner:       true,
		SensitiveFile: true,
		BodyCheck:     true,
		MaxBodyKB:     64,
	}
}

type wafPaths struct {
	install   model.AppInstall
	engineDir string
	httpConf  string
	logFile   string
}

func loadWafPaths() (wafPaths, error) {
	install, err := getAppInstallByKey(constant.AppOpenresty)
	if err != nil {
		return wafPaths{}, errors.New("请先在应用商店安装 OpenResty / install OpenResty from the App Store first")
	}
	return wafPaths{
		install:   install,
		engineDir: path.Join(install.GetPath(), nginxModuleConfDir, "cwaf"),
		httpConf:  path.Join(nginxHTTPConfigDir(install), wafHTTPConfName),
		logFile:   path.Join(install.GetPath(), "www", "cwaf", "cwaf.log"),
	}, nil
}

func readWafConfig(p wafPaths) dto.WafConfig {
	cfg := defaultWafConfig()
	data, err := os.ReadFile(path.Join(p.engineDir, "config.json"))
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		global.LOG.Warnf("waf: invalid config.json, using defaults: %v", err)
		return defaultWafConfig()
	}
	return cfg
}

func (w *WafService) GetStatus() (dto.WafStatus, error) {
	p, err := loadWafPaths()
	if err != nil {
		return dto.WafStatus{Installed: false, Config: defaultWafConfig()}, nil
	}
	_, statErr := os.Stat(p.httpConf)
	cfg := readWafConfig(p)
	return dto.WafStatus{Installed: true, Active: statErr == nil && cfg.Enabled, Config: cfg}, nil
}

func cleanList(items []string, validate func(string) error) ([]string, error) {
	seen := make(map[string]bool)
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		if validate != nil {
			if err := validate(item); err != nil {
				return nil, err
			}
		}
		seen[item] = true
		out = append(out, item)
	}
	if len(out) > wafMaxListEntries {
		return nil, fmt.Errorf("too many entries (max %d)", wafMaxListEntries)
	}
	return out, nil
}

func validateWafIP(item string) error {
	if strings.Contains(item, "/") {
		ip, _, err := net.ParseCIDR(item)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 CIDR: %s", item)
		}
		return nil
	}
	if net.ParseIP(item) == nil {
		return fmt.Errorf("invalid IP: %s", item)
	}
	return nil
}

func validateWafText(item string) error {
	if len(item) > 512 || strings.ContainsAny(item, "\r\n") {
		return fmt.Errorf("invalid entry: %q", item)
	}
	return nil
}

func normalizeWafConfig(req dto.WafConfig) (dto.WafConfig, error) {
	var err error
	if req.Mode != "observe" {
		req.Mode = "block"
	}
	req.RealIPHeader = strings.TrimSpace(req.RealIPHeader)
	if !wafHeaderRe.MatchString(req.RealIPHeader) {
		return req, fmt.Errorf("invalid header name: %s", req.RealIPHeader)
	}
	if req.IPWhite, err = cleanList(req.IPWhite, validateWafIP); err != nil {
		return req, err
	}
	if req.IPBlack, err = cleanList(req.IPBlack, validateWafIP); err != nil {
		return req, err
	}
	for _, list := range []*[]string{&req.URLWhite, &req.URLBlack, &req.UABlack} {
		if *list, err = cleanList(*list, validateWafText); err != nil {
			return req, err
		}
	}
	if req.DisabledHosts, err = cleanList(req.DisabledHosts, func(s string) error {
		if !wafHostRe.MatchString(s) {
			return fmt.Errorf("invalid host: %s", s)
		}
		return nil
	}); err != nil {
		return req, err
	}
	methods := make([]string, 0, len(req.MethodWhite))
	for _, m := range req.MethodWhite {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if !wafMethods[m] {
			return req, fmt.Errorf("invalid HTTP method: %s", m)
		}
		methods = append(methods, m)
	}
	req.MethodWhite, _ = cleanList(methods, nil)
	if req.CC.Requests <= 0 {
		req.CC.Requests = 300
	}
	if req.CC.Window <= 0 {
		req.CC.Window = 60
	}
	if req.CC.BlockSeconds <= 0 {
		req.CC.BlockSeconds = 600
	}
	if req.MaxBodyKB <= 0 || req.MaxBodyKB > 10240 {
		req.MaxBodyKB = 64
	}
	req.LogFile = wafContainerLog
	return req, nil
}

func writeWafEngine(p wafPaths, cfg dto.WafConfig) error {
	if err := os.MkdirAll(p.engineDir, constant.DirPerm); err != nil {
		return err
	}
	if err := writeNginxFileAtomic(path.Join(p.engineDir, "cwaf.lua"), cwaf.Engine); err != nil {
		return err
	}
	blockPage := path.Join(p.engineDir, "block.html")
	if _, err := os.Stat(blockPage); os.IsNotExist(err) {
		if err := os.WriteFile(blockPage, cwaf.BlockPage, constant.FilePerm); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNginxFileAtomic(path.Join(p.engineDir, "config.json"), data); err != nil {
		return err
	}
	// nginx workers may run unprivileged: make the log writable for them.
	logDir := path.Dir(p.logFile)
	if err := os.MkdirAll(logDir, 0o777); err != nil {
		return err
	}
	_ = os.Chmod(logDir, 0o777)
	f, err := os.OpenFile(p.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return err
	}
	_ = f.Close()
	_ = os.Chmod(p.logFile, 0o666)
	return nil
}

func disableLegacyWaf(content string) (string, bool) {
	changed := false
	out := legacyWafLineRe.ReplaceAllStringFunc(content, func(line string) string {
		m := legacyWafLineRe.FindStringSubmatch(line)
		changed = true
		return m[1] + "# " + m[2] + " # disabled by 1Panel community WAF"
	})
	return out, changed
}

func (w *WafService) Update(req dto.WafConfig) error {
	wafMu.Lock()
	defer wafMu.Unlock()

	cfg, err := normalizeWafConfig(req)
	if err != nil {
		return buserr.WithDetail("ErrInvalidParams", err.Error(), err)
	}
	p, err := loadWafPaths()
	if err != nil {
		return err
	}
	rotateWafLog(p.logFile)

	mainConf := nginxMainConfigPath(p.install)
	var mainSnapshot []byte
	oldHTTPConf, oldHTTPErr := os.ReadFile(p.httpConf)
	oldConfig, oldConfigErr := os.ReadFile(path.Join(p.engineDir, "config.json"))

	rollback := func() {
		if mainSnapshot != nil {
			_ = writeNginxFileAtomic(mainConf, mainSnapshot)
		}
		if oldHTTPErr == nil {
			_ = writeNginxFileAtomic(p.httpConf, oldHTTPConf)
		} else {
			_ = os.Remove(p.httpConf)
		}
		if oldConfigErr == nil {
			_ = writeNginxFileAtomic(path.Join(p.engineDir, "config.json"), oldConfig)
		}
	}

	if err := writeWafEngine(p, cfg); err != nil {
		rollback()
		return err
	}

	if cfg.Enabled {
		_, snapshot, err := ensureNginxHTTPIncludeActive(p.install)
		if err != nil {
			rollback()
			return err
		}
		mainSnapshot = snapshot
		content, err := os.ReadFile(mainConf)
		if err != nil {
			rollback()
			return err
		}
		if updated, changed := disableLegacyWaf(string(content)); changed {
			if mainSnapshot == nil {
				mainSnapshot = content
			}
			if err := writeNginxFileAtomic(mainConf, []byte(updated)); err != nil {
				rollback()
				return err
			}
		}
		if err := writeNginxFileAtomic(p.httpConf, cwaf.NginxConf); err != nil {
			rollback()
			return err
		}
	} else {
		if err := os.Remove(p.httpConf); err != nil && !os.IsNotExist(err) {
			rollback()
			return err
		}
	}

	if err := opNginx(p.install.ContainerName, constant.NginxCheck); err != nil {
		rollback()
		return fmt.Errorf("nginx -t failed, changes rolled back: %v", err)
	}
	if err := opNginx(p.install.ContainerName, constant.NginxReload); err != nil {
		rollback()
		_ = opNginx(p.install.ContainerName, constant.NginxReload)
		return err
	}
	return nil
}

func (w *WafService) AddIP(req dto.WafIPReq) error {
	if err := validateWafIP(strings.TrimSpace(req.IP)); err != nil {
		return buserr.WithDetail("ErrInvalidParams", err.Error(), err)
	}
	status, err := w.GetStatus()
	if err != nil {
		return err
	}
	cfg := status.Config
	if req.List == "white" {
		cfg.IPWhite = append(cfg.IPWhite, req.IP)
	} else {
		cfg.IPBlack = append(cfg.IPBlack, req.IP)
	}
	return w.Update(cfg)
}

func rotateWafLog(logFile string) {
	info, err := os.Stat(logFile)
	if err != nil || info.Size() < wafLogMaxBytes {
		return
	}
	_ = os.Rename(logFile, logFile+".1")
	if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY, 0o666); err == nil {
		_ = f.Close()
		_ = os.Chmod(logFile, 0o666)
	}
}

func readWafLogTail(logFile string) ([]byte, error) {
	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := int64(0)
	if info.Size() > wafLogReadBytes {
		offset = info.Size() - wafLogReadBytes
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		}
	}
	return data, nil
}

func (w *WafService) SearchLogs(req dto.WafLogSearch) (int64, []dto.WafLog, error) {
	p, err := loadWafPaths()
	if err != nil {
		return 0, nil, err
	}
	rotateWafLog(p.logFile)
	data, err := readWafLogTail(p.logFile)
	if err != nil {
		return 0, nil, err
	}
	var logs []dto.WafLog
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	ip, rule, host := strings.TrimSpace(req.IP), strings.TrimSpace(req.Rule), strings.ToLower(strings.TrimSpace(req.Host))
	for scanner.Scan() {
		var item dto.WafLog
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			continue
		}
		if ip != "" && !strings.Contains(item.IP, ip) {
			continue
		}
		if rule != "" && item.Rule != rule {
			continue
		}
		if host != "" && !strings.Contains(item.Host, host) {
			continue
		}
		logs = append(logs, item)
	}
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}
	total := int64(len(logs))
	if req.Page <= 0 || req.PageSize <= 0 {
		return total, []dto.WafLog{}, nil
	}
	start := (req.Page - 1) * req.PageSize
	if start >= len(logs) {
		return total, []dto.WafLog{}, nil
	}
	end := start + req.PageSize
	if end > len(logs) {
		end = len(logs)
	}
	return total, logs[start:end], nil
}

func (w *WafService) ClearLogs() error {
	p, err := loadWafPaths()
	if err != nil {
		return err
	}
	if err := os.Truncate(p.logFile, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(p.logFile + ".1")
	return nil
}
