package handlercommon

import (
	"fmt"
	domainaudit "starter-kit/internal/domain/audit"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	"starter-kit/pkg/logger"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
)

func WriteAudit(ctx *gin.Context, auditService interfaceaudit.ServiceAuditInterface, event domainaudit.AuditEvent, scope string) {
	if auditService == nil {
		return
	}

	actorUserID, actorRole := utils.GetActorContext(ctx)
	event.ActorUserID = actorUserID
	event.ActorRole = actorRole
	event.RequestID = utils.GetRequestID(ctx)
	event.IPAddress = ctx.ClientIP()
	event.UserAgent = ctx.GetHeader("User-Agent")

	if err := auditService.Store(event); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelWarn, fmt.Sprintf("[%s][Audit]; failed to store audit trail: %v", scope, err))
	}
}
