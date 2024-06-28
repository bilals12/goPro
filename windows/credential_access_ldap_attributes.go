//go:build windows
// +build windows

/*
ID: 764c9fcd-4c4c-41e6-a0c7-d6c46c2eff66
NAME: Access to a Sensitive LDAP Attribute
CREATED: 2024-05-21
scenario: accessing sensitive AD object attributes that contain credentials
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
ldapsearch to search for `unixUserPassword` attr in LDAP dir
*/

var supported = map[string][]string{
	"windows": {
		"ldapsearch", "-x", "-h", "localhost", "-b", "dc=example,dc=com", "unixUserPassword=*",
	},
}

func test() {
	println("[+] Attempting to access sensitive LDAP attributes")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Sensitive LDAP attribute access was not blocked")
	Endpoint.Stop(101)
}