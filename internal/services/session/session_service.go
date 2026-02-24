package servicesession

import (
	"context"
	"fmt"
	domainsession "starter-kit/internal/domain/session"
	domainuser "starter-kit/internal/domain/user"
	interfacesession "starter-kit/internal/interfaces/session"
	"starter-kit/utils"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ServiceSession struct {
	SessionRepo interfacesession.RepoSessionInterface
}

func NewSessionService(sessionRepo interfacesession.RepoSessionInterface) *ServiceSession {
	return &ServiceSession{
		SessionRepo: sessionRepo,
	}
}

func (s *ServiceSession) CreateSession(ctx context.Context, user *domainuser.Users, token string, requestMeta domainsession.RequestMeta) (*domainsession.Session, error) {
	sessionID := uuid.New().String()

	jwtExpHours := utils.GetEnv("JWT_EXP", 24).(int)
	expiresAt := time.Now().Add(time.Hour * time.Duration(jwtExpHours))

	userAgent := requestMeta.UserAgent
	deviceInfo := requestMeta.DeviceInfo
	if deviceInfo == "" {
		deviceInfo = extractDeviceInfo(userAgent)
	}

	session := &domainsession.Session{
		SessionID:    sessionID,
		UserID:       user.Id,
		Email:        user.Email,
		Role:         user.Role,
		Token:        token,
		DeviceInfo:   deviceInfo,
		IP:           requestMeta.IP,
		UserAgent:    userAgent,
		LoginAt:      time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
	}

	if err := s.SessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

func (s *ServiceSession) ValidateSession(ctx context.Context, token string) (*domainsession.Session, error) {
	session, err := s.SessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}

	if time.Now().After(session.ExpiresAt) {
		if delErr := s.SessionRepo.Delete(ctx, session.SessionID); delErr != nil {
			fmt.Printf("Failed to delete expired session: %v\n", delErr)
		}
		return nil, fmt.Errorf("session expired")
	}

	if err := s.SessionRepo.UpdateActivity(ctx, session.SessionID); err != nil {
		fmt.Printf("Failed to update session activity: %v\n", err)
	}

	return session, nil
}

func (s *ServiceSession) GetUserSessions(ctx context.Context, userID string, currentSessionID string) ([]*domainsession.SessionInfo, error) {
	sessions, err := s.SessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessionInfos := make([]*domainsession.SessionInfo, 0, len(sessions))
	for _, session := range sessions {
		info := &domainsession.SessionInfo{
			SessionID:        session.SessionID,
			DeviceInfo:       session.DeviceInfo,
			IP:               session.IP,
			LoginAt:          session.LoginAt,
			LastActivity:     session.LastActivity,
			IsCurrentSession: session.SessionID == currentSessionID,
		}
		sessionInfos = append(sessionInfos, info)
	}

	return sessionInfos, nil
}

func (s *ServiceSession) DestroySession(ctx context.Context, sessionID string) error {
	return s.SessionRepo.Delete(ctx, sessionID)
}

func (s *ServiceSession) DestroySessionByToken(ctx context.Context, token string) error {
	session, err := s.SessionRepo.GetByToken(ctx, token)
	if err != nil {
		return err
	}
	return s.SessionRepo.Delete(ctx, session.SessionID)
}

func (s *ServiceSession) GetSessionByToken(ctx context.Context, token string) (*domainsession.Session, error) {
	return s.SessionRepo.GetByToken(ctx, token)
}

func (s *ServiceSession) GetSessionBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error) {
	return s.SessionRepo.GetBySessionID(ctx, sessionID)
}

func (s *ServiceSession) DestroyAllUserSessions(ctx context.Context, userID string) error {
	return s.SessionRepo.DeleteByUserID(ctx, userID)
}

func (s *ServiceSession) DestroyOtherSessions(ctx context.Context, userID string, currentSessionID string) error {
	sessions, err := s.SessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.SessionID != currentSessionID {
			if err := s.SessionRepo.Delete(ctx, session.SessionID); err != nil {
				return err
			}
		}
	}

	return nil
}

func extractDeviceInfo(userAgent string) string {
	if strings.Contains(userAgent, "Mobile") || strings.Contains(userAgent, "Android") || strings.Contains(userAgent, "iPhone") {
		if strings.Contains(userAgent, "Android") {
			return "Android Mobile"
		} else if strings.Contains(userAgent, "iPhone") {
			return "iOS Mobile"
		}
		return "Mobile Device"
	} else if strings.Contains(userAgent, "iPad") || strings.Contains(userAgent, "Tablet") {
		return "Tablet"
	} else if strings.Contains(userAgent, "Windows") {
		return "Windows PC"
	} else if strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS") {
		return "Mac"
	} else if strings.Contains(userAgent, "Linux") {
		return "Linux"
	}

	return "Unknown Device"
}

var _ interfacesession.ServiceSessionInterface = (*ServiceSession)(nil)
