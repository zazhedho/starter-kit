package handlerpermission

import (
	domainaudit "starter-kit/internal/domain/audit"
	handlercommon "starter-kit/internal/handlers/http/common"

	"github.com/gin-gonic/gin"
)

func (h *PermissionHandler) writeAudit(ctx *gin.Context, event domainaudit.AuditEvent) {
	handlercommon.WriteAudit(ctx, h.AuditService, event, "PermissionHandler")
}
