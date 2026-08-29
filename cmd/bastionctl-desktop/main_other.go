//go:build !windows

package main

import "fmt"

var version = "dev"

func main() {
	fmt.Printf("bastionctl desktop %s поддерживает Windows; серверная часть поддерживает Ubuntu\n", version)
}
