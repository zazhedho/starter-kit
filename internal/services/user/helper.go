package serviceuser

import (
	"errors"
	"regexp"
	domainuser "starter-kit/internal/domain/user"
	interfacerole "starter-kit/internal/interfaces/role"
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
