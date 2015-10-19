package mauth

import (
	"fmt"
	"github.com/mabetle/mcore"
	"strings"
)

const ROLE_PREFIX = "ROLE_"

var ResRoleMap = [][]string{}

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

func QualifyRolesStr(roles string) string {
	return strings.Join(QualifyRoles(roles), ",")
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

// AddResRoleMap
func AddResRoleMap(res, roles string) {
	res = strings.ToLower(res)
	res = strings.TrimSpace(res)
	roles = QualifyRolesStr(roles)
	item := []string{res, roles}
	// overide exists res
	exist := false
	for index, vs := range ResRoleMap {
		rres := vs[0]
		if rres == res {
			exist = true
			ResRoleMap[index] = []string{res, roles}
		}
	}
	if !exist {
		ResRoleMap = append(ResRoleMap, item)
	}
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

// getResNeedRoles
func getResNeedRoles(checkRes string) string {
	sb := mcore.NewStringBuffer()
	for _, rm := range ResRoleMap {
		if len(rm) < 2 {
			continue
		}
		res := rm[0]
		role := rm[1]
		if isMatch(res, checkRes) {
			sb.Append(role, ",")
		}
	}
	roles := sb.String()
	return strings.TrimSuffix(roles, ",")
}

// IsCanAccessRes
func IsCanAccessRes(checkRes, userRoles string) bool {
	checkRes = strings.ToLower(checkRes)
	checkRes = strings.TrimSpace(checkRes)
	needRoles := getResNeedRoles(checkRes)
	return CheckRoles(needRoles, userRoles)
}

// PrintIsCanAccessRes
func PrintIsCanAccessRes(checkRes, userRoles string, expect bool) {
	b := IsCanAccessRes(checkRes, userRoles)
	if b == expect {
		fmt.Printf("Passed\n")
		return
	}
	fmt.Printf("CheckAuth, Res:%s UserRoles: %s Result:%v Expect:%v\n", checkRes, userRoles, b, expect)
}

//
func PrintResRoleAuthMap() {
	fmt.Printf("***ResRoleAuth Config***\n")
	for _, rm := range ResRoleMap {
		if len(rm) < 2 {
			continue
		}
		fmt.Printf("\t%s : %s\n", rm[0], rm[1])
	}
}

// LoadAuthMapFile
func LoadAuthMapFile(location string) error {
	fmt.Printf("Load Res Auth Config from File: %s\n", location)
	lines, err := mcore.ReadFileLines(location)
	if err != nil {
		fmt.Printf("Error Load Auth File: %s\n", err)
		return err
	}
	for _, line := range lines {
		ms := mcore.NewString(line).TrimSpace()
		// skip comment line or blank line or no = line
		if ms.IsHasPrefix("#") || ms.IsBlank() || !ms.IsContains("=") {
			continue
		}
		rm := ms.Split("=")
		if len(rm) < 2 {
			continue
		}
		res := strings.TrimSpace(rm[0])
		role := strings.TrimSpace(rm[1])
		AddResRoleMap(res, role)
	}
	return nil
}

func InitAuthMap() {
	fmt.Printf("***Init AuthMap\n")
	// commons
	AddResRoleMap("/Demo*", "DEMO")
	AddResRoleMap("/Admin*", "ADMIN")

	// static assets
	AddResRoleMap("/public*", "ALL")
	AddResRoleMap("/mps/public*", "ALL")
	AddResRoleMap("/fav*", "ALL")
	AddResRoleMap("/robots*", "ALL")
	AddResRoleMap("/logo*", "ALL")
	AddResRoleMap("/assets*", "ALL")

	// for old spring
	AddResRoleMap("/j_spring*", "ALL")

	// some pages
	AddResRoleMap("/Help/*", "ALL")

	AddResRoleMap("/AppAjax/*", "ALL")
	AddResRoleMap("/Account*", "ALL")
	AddResRoleMap("/AccountAjax/", "ALL")
}
