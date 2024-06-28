//go:build linux
// +build linux

/*
ID: 7acb2de3-8465-472a-8d9c-ccd7b73d0ed8
NAME: Potential Privilege Escalation through Writable Docker Socket
CREATED: 2024-05-21
*/
package main

import (
	_ "embed"
	"os/exec"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
use `docker run` to create container that mounts root fs `/` to container `/mnt` dir
write text to `/mnt/tmp/testfile` on host filesystem
*/

var supported = map[string][]string{
	"linux": {
		"docker", "run", "--rm", "-v", "/:/mnt", "alpine", "sh", "-c", "echo 'testing privesc' > /mnt/tmp/testfile",
	},
}

func test() {
	println("[+] attempting to escalate privs via docker socket")
	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Run()
	if err != nil {
		println("[+] privesc prevented")
		Endpoint.Stop(100)
		return
	}
	println("[-] privesc thru docker socket not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}