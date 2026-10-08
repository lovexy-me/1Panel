package dto

type WafCCConfig struct {
	Enabled      bool `json:"enabled"`
	Requests     int  `json:"requests" validate:"min=1,max=1000000"`
	Window       int  `json:"window" validate:"min=1,max=86400"`
	BlockSeconds int  `json:"blockSeconds" validate:"min=1,max=2592000"`
}

// WafConfig is the community WAF configuration. It is written as JSON for
// the Lua engine, so field names are shared with cwaf.lua.
type WafConfig struct {
	Enabled       bool        `json:"enabled"`
	Mode          string      `json:"mode" validate:"oneof=block observe"`
	RealIPHeader  string      `json:"realIpHeader"`
	IPWhite       []string    `json:"ipWhite"`
	IPBlack       []string    `json:"ipBlack"`
	URLWhite      []string    `json:"urlWhite"`
	URLBlack      []string    `json:"urlBlack"`
	UABlack       []string    `json:"uaBlack"`
	MethodWhite   []string    `json:"methodWhite"`
	DisabledHosts []string    `json:"disabledHosts"`
	CC            WafCCConfig `json:"cc"`
	Sqli          bool        `json:"sqli"`
	Xss           bool        `json:"xss"`
	Traversal     bool        `json:"traversal"`
	Rce           bool        `json:"rce"`
	Scanner       bool        `json:"scanner"`
	SensitiveFile bool        `json:"sensitiveFile"`
	BodyCheck     bool        `json:"bodyCheck"`
	MaxBodyKB     int         `json:"maxBodyKB" validate:"min=1,max=10240"`
	LogFile       string      `json:"logFile,omitempty"`
}

type WafStatus struct {
	Installed bool      `json:"installed"`
	Active    bool      `json:"active"`
	Config    WafConfig `json:"config"`
}

type WafLogSearch struct {
	PageInfo
	IP   string `json:"ip"`
	Rule string `json:"rule"`
	Host string `json:"host"`
}

type WafLog struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Method string `json:"method"`
	URI    string `json:"uri"`
	Rule   string `json:"rule"`
	Match  string `json:"match"`
	Action string `json:"action"`
	UA     string `json:"ua"`
	ID     string `json:"id"`
}

type WafIPReq struct {
	IP   string `json:"ip" validate:"required"`
	List string `json:"list" validate:"oneof=white black"`
}
