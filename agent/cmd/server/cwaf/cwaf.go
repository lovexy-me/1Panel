// Package cwaf embeds the community WAF engine (LuaJIT, runs inside OpenResty).
package cwaf

import _ "embed"

//go:embed cwaf.lua
var Engine []byte

//go:embed waf.conf
var NginxConf []byte

//go:embed block.html
var BlockPage []byte
