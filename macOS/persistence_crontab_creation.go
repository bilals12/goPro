//go:build darwin
// +build darwin

/*
ID: 530178da-92ea-43ce-94c2-8877a826783d
NAME: Suspicious CronTab Creation or Modification
CREATED: 2024-06-28
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"darwin": {"/bin/sh", "-c", `echo "*/5 * * * * /usr/bin/python3 /path/to/suspicious_script.py" > /private/var/at/tabs/root`},
}

func test() {
	println("[+] Creating a suspicious crontab entry using Python")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Crontab entry was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
