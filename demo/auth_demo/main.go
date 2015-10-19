package main

import (
	"fmt"
	"github.com/mabetle/mauth"
)

func Check() {
	mauth.PrintIsCanAccessRes("/admin", "DEMO", false)
	mauth.PrintIsCanAccessRes("/Demo", "Admin", false)

	mauth.PrintIsCanAccessRes("/admin", "Admin", true)
	mauth.PrintIsCanAccessRes("/mps/public", "Admin", true)
	mauth.PrintIsCanAccessRes("/public", "Admin", true)
	mauth.PrintIsCanAccessRes("/fav", "Demo", true)
	mauth.PrintIsCanAccessRes("/fav", "Admin", true)
	mauth.PrintIsCanAccessRes("/fav", "USER,NONE", true)

}

func main() {
	//mauth.InitAuthMap()
	err := mauth.LoadAuthMapFile("../../auth_tml.conf")
	if err != nil {
		fmt.Printf("%s\n", err)
	}
	mauth.PrintResRoleAuthMap()

	Check()

	fmt.Println("")
}
