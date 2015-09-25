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

}

func main() {
	mauth.InitAuthMap()

	Check()

	fmt.Println("")
}
