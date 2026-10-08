package router

import (
	v2 "github.com/1Panel-dev/1Panel/agent/app/api/v2"
	"github.com/gin-gonic/gin"
)

type WafRouter struct{}

func (a *WafRouter) InitRouter(Router *gin.RouterGroup) {
	wafRouter := Router.Group("websites/waf")
	baseApi := v2.ApiGroupApp.BaseApi
	{
		wafRouter.GET("/status", baseApi.GetWafStatus)
		wafRouter.POST("/update", baseApi.UpdateWafConfig)
		wafRouter.POST("/ip", baseApi.AddWafIP)
		wafRouter.POST("/logs", baseApi.SearchWafLogs)
		wafRouter.POST("/logs/clear", baseApi.ClearWafLogs)
	}
}
