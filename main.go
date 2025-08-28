//go:generate swag init
package main

import "github.com/intraware/rodan-authify/cmd"

func main() {
	cmd.Run()
}
