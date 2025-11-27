package router

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"team-leader-development-program/infrastructure/database"
	menuHandler "team-leader-development-program/internal/handlers/http/menu"
	permissionHandler "team-leader-development-program/internal/handlers/http/permission"
	roleHandler "team-leader-development-program/internal/handlers/http/role"
	sessionHandler "team-leader-development-program/internal/handlers/http/session"
	userHandler "team-leader-development-program/internal/handlers/http/user"
	authRepo "team-leader-development-program/internal/repositories/auth"
	menuRepo "team-leader-development-program/internal/repositories/menu"
	permissionRepo "team-leader-development-program/internal/repositories/permission"
	roleRepo "team-leader-development-program/internal/repositories/role"
	sessionRepo "team-leader-development-program/internal/repositories/session"
	userRepo "team-leader-development-program/internal/repositories/user"
	menuSvc "team-leader-development-program/internal/services/menu"
	permissionSvc "team-leader-development-program/internal/services/permission"
	roleSvc "team-leader-development-program/internal/services/role"
	sessionSvc "team-leader-development-program/internal/services/session"
	userSvc "team-leader-development-program/internal/services/user"
	"team-leader-development-program/middlewares"
	"team-leader-development-program/pkg/logger"
	"team-leader-development-program/pkg/security"
	"team-leader-development-program/utils"
)

type Routes struct {
	App *gin.Engine
	DB  *gorm.DB
}

func NewRoutes() *Routes {
	app := gin.Default()

	app.Use(middlewares.CORS())
	app.Use(gin.CustomRecovery(middlewares.ErrorHandler))
	app.Use(middlewares.SetContextId())

	app.GET("/healthcheck", func(ctx *gin.Context) {
		logger.WriteLog(logger.LogLevelDebug, "ClientIP: "+ctx.ClientIP())
		ctx.JSON(http.StatusOK, gin.H{
			"message": "OK!!",
		})
	})

	return &Routes{
		App: app,
	}
}

func (r *Routes) UserRoutes() {
	blacklistRepo := authRepo.NewBlacklistRepo(r.DB)
	repo := userRepo.NewUserRepo(r.DB)
	rRepo := roleRepo.NewRoleRepo(r.DB)
	pRepo := permissionRepo.NewPermissionRepo(r.DB)
	uc := userSvc.NewUserService(repo, blacklistRepo, rRepo, pRepo)

	// Setup login limiter if Redis is available
	redisClient := database.GetRedisClient()
	var loginLimiter security.LoginLimiter
	if redisClient != nil {
		loginLimiter = security.NewRedisLoginLimiter(
			redisClient,
			utils.GetEnv("LOGIN_ATTEMPT_LIMIT", 5).(int),
			time.Duration(utils.GetEnv("LOGIN_ATTEMPT_WINDOW_SECONDS", 60).(int))*time.Second,
			time.Duration(utils.GetEnv("LOGIN_BLOCK_DURATION_SECONDS", 300).(int))*time.Second,
		)
	}

	h := userHandler.NewUserHandler(uc, loginLimiter)
	mdw := middlewares.NewMiddleware(blacklistRepo)

	// Setup register rate limiter
	registerLimit := utils.GetEnv("REGISTER_RATE_LIMIT", 5).(int)
	registerWindowSeconds := utils.GetEnv("REGISTER_RATE_WINDOW_SECONDS", 60).(int)
	if registerWindowSeconds <= 0 {
		registerWindowSeconds = 60
	}
	registerLimiter := middlewares.IPRateLimitMiddleware(
		redisClient,
		"user_register",
		registerLimit,
		time.Duration(registerWindowSeconds)*time.Second,
	)

	user := r.App.Group("/api/user")
	{
		user.POST("/register", registerLimiter, h.Register)
		user.POST("/login", h.Login)
		user.POST("/forgot-password", h.ForgotPassword)
		user.POST("/reset-password", h.ResetPassword)

		userPriv := user.Group("").Use(mdw.AuthMiddleware())
		{
			userPriv.POST("/logout", h.Logout)
			userPriv.GET("", h.GetUserByAuth)
			userPriv.GET("/:id", mdw.RoleMiddleware(utils.RoleAdmin, utils.RoleStaff), h.GetUserById)
			userPriv.PUT("", h.Update)
			userPriv.PUT("/:id", mdw.RoleMiddleware(utils.RoleAdmin), h.UpdateUserById)
			userPriv.PUT("/change/password", h.ChangePassword)
			userPriv.DELETE("", h.Delete)
			userPriv.DELETE("/:id", mdw.RoleMiddleware(utils.RoleAdmin), h.DeleteUserById)
		}
	}

	r.App.GET("/api/users", mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleSuperAdmin, utils.RoleAdmin, utils.RoleStaff), h.GetAllUsers)
}

func (r *Routes) RoleRoutes() {
	repoRole := roleRepo.NewRoleRepo(r.DB)
	repoPermission := permissionRepo.NewPermissionRepo(r.DB)
	repoMenu := menuRepo.NewMenuRepo(r.DB)
	svc := roleSvc.NewRoleService(repoRole, repoPermission, repoMenu)
	h := roleHandler.NewRoleHandler(svc)
	mdw := middlewares.NewMiddleware(authRepo.NewBlacklistRepo(r.DB))

	r.App.GET("/api/roles", mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin), h.GetAll)

	role := r.App.Group("/api/role").Use(mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin))
	{
		role.POST("", h.Create)
		role.GET("/:id", h.GetByID)
		role.PUT("/:id", h.Update)
		role.DELETE("/:id", h.Delete)

		role.POST("/:id/permissions", h.AssignPermissions)
		role.POST("/:id/menus", h.AssignMenus)
	}
}

func (r *Routes) PermissionRoutes() {
	repo := permissionRepo.NewPermissionRepo(r.DB)
	svc := permissionSvc.NewPermissionService(repo)
	h := permissionHandler.NewPermissionHandler(svc)
	mdw := middlewares.NewMiddleware(authRepo.NewBlacklistRepo(r.DB))

	r.App.GET("/api/permissions", mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin), h.GetAll)
	r.App.GET("/api/permissions/me", mdw.AuthMiddleware(), h.GetUserPermissions)

	permission := r.App.Group("/api/permission").Use(mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin))
	{
		permission.POST("", h.Create)
		permission.GET("/:id", h.GetByID)
		permission.PUT("/:id", h.Update)
		permission.DELETE("/:id", h.Delete)
	}
}

func (r *Routes) MenuRoutes() {
	repo := menuRepo.NewMenuRepo(r.DB)
	svc := menuSvc.NewMenuService(repo)
	h := menuHandler.NewMenuHandler(svc)
	mdw := middlewares.NewMiddleware(authRepo.NewBlacklistRepo(r.DB))

	r.App.GET("/api/menus/active", mdw.AuthMiddleware(), h.GetActiveMenus)
	r.App.GET("/api/menus/me", mdw.AuthMiddleware(), h.GetUserMenus)
	r.App.GET("/api/menus", mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin), h.GetAll)

	menu := r.App.Group("/api/menu").Use(mdw.AuthMiddleware(), mdw.RoleMiddleware(utils.RoleAdmin))
	{
		menu.POST("", h.Create)
		menu.GET("/:id", h.GetByID)
		menu.PUT("/:id", h.Update)
		menu.DELETE("/:id", h.Delete)
	}
}

func (r *Routes) SessionRoutes() {
	redisClient := database.GetRedisClient()
	if redisClient == nil {
		logger.WriteLog(logger.LogLevelDebug, "Redis not available, session routes will not be registered")
		return
	}

	repo := sessionRepo.NewSessionRepository(redisClient)
	svc := sessionSvc.NewSessionService(repo)
	h := sessionHandler.NewSessionHandler(svc)
	mdw := middlewares.NewMiddleware(authRepo.NewBlacklistRepo(r.DB))

	sessionGroup := r.App.Group("/api/user").Use(mdw.AuthMiddleware())
	{
		sessionGroup.GET("/sessions", h.GetActiveSessions)
		sessionGroup.DELETE("/session/:session_id", h.RevokeSession)
		sessionGroup.POST("/sessions/revoke-others", h.RevokeAllOtherSessions)
	}

	logger.WriteLog(logger.LogLevelInfo, "Session management routes registered")
}
