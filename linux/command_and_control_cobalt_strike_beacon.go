//go:build linux
// +build linux

/*
ID: cf53f532-9cc9-445a-9ae7-fced307ec53c
NAME: Cobalt Strike Command and Control Beacon
CREATED: 2023-12-18
scenario: establishing a connection to a C2 server
send GET request that matches CS's DGA [Domain Generation Algorithm]
*/

package main

import (
    "net"
    "time"
    Network "github.com/preludeorg/test/network"
    Endpoint "github.com/preludeorg/test/endpoint"
)

func test() {
    address := "strike.com:443" // replace with C2 server

    conn, err := net.DialTimeout("tcp", address, 10*time.Second)
    if err != nil {
        Endpoint.Say("[+] C2 server connection attempt blocked/failed")
        Endpoint.Stop(126)
    }
    defer conn.Close()


    // simulate DGA pattern
    httpClient := Network.NewHTTPRequest("https://example.com/stage.20231218.example", nil)
    response, err := httpClient.GET(Network.RequestParameters{})
    if err != nil {
        Endpoint.Say("[-] HTTP request to C2 server failed")
        Endpoint.Stop(126)
    }

    if response.StatusCode == 200 {
        Endpoint.Say("[+] C2 server connection + HTTP request successful")
        Endpoint.Stop(101) // unprotected
    } else {
        Endpoint.Say("[-] C2 server responded with unexpected status")
        Endpoint.Stop(126)
    }
}

func main() {
    Endpoint.Start(test)
}