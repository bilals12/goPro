//go:build linux
// +build linux

/*
ID: 34fde489-94b0-4500-a76f-b8a157cf9269
NAME: Accepted Default Telnet Port Connection
CREATED: 2024-05-21
scenario: detect telnet traffic
*/

package main

import (
	"fmt"
	"net"
	"time"

	Network "github.com/preludeorg/test/network"
	Endpoint "github.com/preludeorg/test/endpoint"
)

// telnet test
func test() {
	address := "localhost:23"

	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		Endpoint.Say("[-] telnet connection failed")
		Endpoint.Stop(126)
	}
	defer conn.Close()

	Endpoint.Say("[+] telnet connection established to localhost on port 23")
	Endpoint.Stop(101) // unprotected
}

func main() {
	Endpoint.Start(test)
}