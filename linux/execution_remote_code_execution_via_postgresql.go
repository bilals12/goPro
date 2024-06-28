//go:build linux
// +build linux

/*
ID: 2a692072-d78d-42f3-a48a-775677d79c4e
NAME: Potential Code Execution via PostgreSQL
CREATED: 2024-05-21
scenario: using `psql` to execute SQL command that creates table and shell command
*/
package main

import (
	_ "embed"
	"os/exec"
	"runtime"
	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"linux": {
		"psql", "-c", "CREATE TABLE test (data text); COPY test FROM PROGRAM 'sh -c echo hacked > /tmp/testfile';",
	},
}

func test() {
	println("[+] attempting to execute code within postgresql")
	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Run()
	if err != nil {
		println("[+] execution prevented")
		Endpoint.Stop(100)
		return
	}
	println("[-] arbitrary code execution within postgresql was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}