package mauth

import (
	"fmt"
	"github.com/mabetle/mcore"
	"strings"
)

const ROLE_PREFIX = "ROLE_"

var ResRoleMap = make(map[string]string)

func QualifyRole(role string) string {
	role = strings.ToUpper(role)
	role = strings.TrimSpace(role)

	if !strings.HasPrefix(role, ROLE_PREFIX) {
		role = ROLE_PREFIX + role
	}
	return role
}

func QualifyRoles(roles string) []string {
	result := []string{}
	for _, role := range strings.Split(roles, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		role = QualifyRole(role)
		result = append(result, role)
	}
	return result
}

func CheckRoles(needRoles, userRoles string) bool {
	// not found means no rights restrict
	if needRoles == "" {
		return true
	}
	// if has all means no rights restrict
	if strings.Contains(needRoles, "ALL") {
		return true
	}
	// if user roles null means not login yet.
	if userRoles == "" {

	}

	needRolesA := QualifyRoles(needRoles)
	userRolesA := QualifyRoles(userRoles)

	// user has need roles
	for _, checkRole := range userRolesA {
		if strings.TrimSpace(checkRole) == "" {
			continue
		}
		checkRole = QualifyRole(checkRole)
		if mcore.NewString(checkRole).IsInArrayIgnoreCase(needRolesA) {
			return true
		}
	}
	// not found, no rights
	return false
}

func AddResRoleMap(res, role string) {
	res = strings.ToLower(res)
	res = strings.TrimSpace(res)
	ResRoleMap[res] = QualifyRole(role)
}

func isMatch(res, checkRes string) bool {
	if res == checkRes {
		return true
	}

	rolePrefix := strings.TrimSuffix(res, "*")

	if strings.HasSuffix(res, "*") && strings.HasPrefix(checkRes, rolePrefix) {
		return true
	}
	return false
}

func getResNeedRoles(checkRes string) string {
	sb := mcore.NewStringBuffer()
	for res, role := range ResRoleMap {
		if isMatch(res, checkRes) {
			sb.Append(role, ",")
		}
	}
	roles := sb.String()
	return strings.TrimSuffix(roles, ",")
}

func IsCanAccessRes(checkRes, userRoles string) bool {
	checkRes = strings.ToLower(checkRes)
	checkRes = strings.TrimSpace(checkRes)
	needRoles := getResNeedRoles(checkRes)
	return CheckRoles(needRoles, userRoles)
}

func PrintIsCanAccessRes(checkRes, userRoles string, expect bool) {
	b := IsCanAccessRes(checkRes, userRoles)
	if b == expect {
		fmt.Printf("Passed\n")
		return
	}
	fmt.Printf("CheckAuth, Res:%s UserRoles: %s Result:%v Expect:%v\n", checkRes, userRoles, b, expect)
}

func InitAuthMap() {
	fmt.Printf("***Init AuthMap\n")
	AddResRoleMap("/Demo*", "DEMO")
	AddResRoleMap("/Admin*", "ADMIN")

	AddResRoleMap("/Public*", "ALL")
	AddResRoleMap("/AppAjax/*", "ALL")
	AddResRoleMap("/mps/Public*", "ALL")
	AddResRoleMap("/fav*", "ALL")
	AddResRoleMap("/Account/", "ALL")
	AddResRoleMap("/AccountAjax/", "ALL")
}
