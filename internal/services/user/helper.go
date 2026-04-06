package serviceuser

import (
	"errors"
	"net/mail"
	"regexp"
	domainpermission "starter-kit/internal/domain/permission"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	interfacerole "starter-kit/internal/interfaces/role"
	"starter-kit/utils"
	"strings"
)

func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return errors.New("password must contain at least 1 lowercase letter (a-z)")
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return errors.New("password must contain at least 1 uppercase letter (A-Z)")
	}

	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasNumber {
		return errors.New("password must contain at least 1 number (0-9)")
	}

	hasSymbol := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password)
	if !hasSymbol {
		return errors.New("password must contain at least 1 symbol (!@#$%^&*...)")
	}

	return nil
}

func buildUserAuthResponse(user domainuser.Users, permissions []string) map[string]interface{} {
	if permissions == nil {
		permissions = []string{}
	}

	return map[string]interface{}{
		"id":          user.Id,
		"name":        user.Name,
		"email":       user.Email,
		"phone":       user.Phone,
		"role":        user.Role,
		"permissions": permissions,
		"created_at":  user.CreatedAt,
		"updated_at":  user.UpdatedAt,
	}
}

func findRoleIDByName(roleRepo interfacerole.RepoRoleInterface, roleName string) (*string, bool) {
	roleEntity, err := roleRepo.GetByName(roleName)
	if err != nil || roleEntity.Id == "" {
		return nil, false
	}

	return &roleEntity.Id, true
}

func hasPermission(permissions []domainpermission.Permission, resource, action string) bool {
	for _, permission := range permissions {
		if permission.Resource == resource && permission.Action == action {
			return true
		}
	}

	return false
}

func resolveLoginIdentifier(req dto.Login) (string, error) {
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		identifier = strings.TrimSpace(req.Email)
	}

	if identifier == "" {
		return "", errors.New("identifier or email is required")
	}

	if strings.Contains(identifier, "@") {
		sanitizedEmail := utils.SanitizeEmail(identifier)
		if _, err := mail.ParseAddress(sanitizedEmail); err != nil {
			return "", errors.New("identifier must be a valid email or phone number")
		}
		return sanitizedEmail, nil
	}

	normalizedPhone := utils.NormalizePhoneTo62(identifier)
	if len(normalizedPhone) < 9 || len(normalizedPhone) > 15 {
		return "", errors.New("identifier must be a valid email or phone number")
	}

	return normalizedPhone, nil
}
