package v2

import (
	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/gin-gonic/gin"
)

// @Tags WAF
// @Summary Load community WAF status and config
// @Success 200 {object} dto.WafStatus
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /websites/waf/status [get]
func (b *BaseApi) GetWafStatus(c *gin.Context) {
	data, err := wafService.GetStatus()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, data)
}

// @Tags WAF
// @Summary Update community WAF config (enable/disable included)
// @Accept json
// @Param request body dto.WafConfig true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /websites/waf/update [post]
func (b *BaseApi) UpdateWafConfig(c *gin.Context) {
	var req dto.WafConfig
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.Update(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Add an IP to the WAF white or black list
// @Accept json
// @Param request body dto.WafIPReq true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /websites/waf/ip [post]
func (b *BaseApi) AddWafIP(c *gin.Context) {
	var req dto.WafIPReq
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.AddIP(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Search WAF block logs
// @Accept json
// @Param request body dto.WafLogSearch true "request"
// @Success 200 {object} dto.PageResult
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /websites/waf/logs [post]
func (b *BaseApi) SearchWafLogs(c *gin.Context) {
	var req dto.WafLogSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	total, items, err := wafService.SearchLogs(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
}

// @Tags WAF
// @Summary Clear WAF block logs
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /websites/waf/logs/clear [post]
func (b *BaseApi) ClearWafLogs(c *gin.Context) {
	if err := wafService.ClearLogs(); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}
