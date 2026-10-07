package middleware

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/repo"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/1Panel-dev/1Panel/core/utils/common"
	"github.com/1Panel-dev/1Panel/core/utils/security"
	"github.com/gin-gonic/gin"
)

func WhiteAllow() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("X-Panel-Local-Token")
		remoteIP := common.GetRealClientIP(c)
		if isLocalSyncRequest(c.Request.URL.Path, remoteIP, tokenString) {
			c.Set("LOCAL_REQUEST", true)
			c.Next()
			return
		}

		settingRepo := repo.NewISettingRepo()
		trustedProxies, err := settingRepo.GetValueByKey("AllowIPTrustedProxies")
		if err != nil {
			helper.InternalServer(c, err)
			return
		}
		clientIP := common.ResolveClientIP(c, trustedProxies)

		allowIPs, err := settingRepo.GetValueByKey("AllowIPs")
		if err != nil {
			helper.InternalServer(c, err)
			return
		}

		if len(allowIPs) == 0 {
			c.Next()
			return
		}
		for _, ip := range strings.Split(allowIPs, ",") {
			if len(ip) == 0 {
				continue
			}
			if ip == clientIP || (strings.Contains(ip, "/") && common.CheckIpInCidr(ip, clientIP)) {
				c.Next()
				return
			}
		}
		code := security.LoadErrCode()
		helper.ErrWithHtml(c, code, "err_ip_limit")
	}
}

func isLocalSyncRequest(reqPath, clientIP, token string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil || !ip.IsLoopback() {
		return false
	}

	switch reqPath {
	case "/api/v2/core/xpack/sync/ssl", "/api/v2/core/settings/ssl/reload":
		return isValidLocalToken(token)
	default:
		return false
	}
}

// isValidLocalToken verifies the daily token the agent derives from the shared
// secret in <InstallDir>/1panel/tmp/.secret. A non-empty header alone is not
// enough: behind a reverse proxy on the same host every request is loopback.
func isValidLocalToken(token string) bool {
	if len(token) != 16 {
		return false
	}
	data, err := os.ReadFile(path.Join(global.CONF.Base.InstallDir, "1panel/tmp/.secret"))
	if err != nil {
		return false
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return false
	}
	now := time.Now()
	for _, day := range []time.Time{now, now.Add(-24 * time.Hour)} {
		h := md5.Sum([]byte(secret + "-" + day.Format("2006-01-02")))
		expected := hex.EncodeToString(h[:])[:16]
		if subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1 {
			return true
		}
	}
	return false
}
