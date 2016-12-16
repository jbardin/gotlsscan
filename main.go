package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type tlsKV struct {
	name string
	val  uint16
}

var (
	// use this for Dial and Handshake
	timeout = 10 * time.Second

	host     string
	port     string
	insecure bool
)

var versions = []tlsKV{
	{"SSL30 (DISABLED)", tls.VersionSSL30},
	{"TLS1.0", tls.VersionTLS10},
	{"TLS1.1", tls.VersionTLS11},
	{"TLS1.2", tls.VersionTLS12},
}

var ciphers = []tlsKV{
	{"TLS_RSA_WITH_RC4_128_SHA (DISABLED)", tls.TLS_RSA_WITH_RC4_128_SHA},
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	{"TLS_RSA_WITH_AES_128_CBC_SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	{"TLS_RSA_WITH_AES_256_CBC_SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA},
	{"TLS_RSA_WITH_AES_128_CBC_SHA256", tls.TLS_RSA_WITH_AES_128_CBC_SHA256},
	{"TLS_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	{"TLS_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
	{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (DISABLED)", tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
	{"TLS_ECDHE_RSA_WITH_RC4_128_SHA (DISABLED)", tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
	{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
	{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
}

func main() {
	flag.StringVar(&host, "host", "", "host")
	flag.StringVar(&port, "port", "443", "port")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.Parse()

	if host == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
	}

	for _, v := range versions {
		fmt.Println("Testing", v.name)
		for _, c := range ciphers {
			cfg.MinVersion = v.val
			cfg.MaxVersion = v.val
			cfg.CipherSuites = []uint16{c.val}

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
			if err != nil {
				log.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(timeout))

			tlsConn := tls.Client(conn, cfg)
			err = tlsConn.Handshake()
			if err != nil {
				e := err.Error()
				if !strings.Contains(e, "handshake failure") && !strings.Contains(e, "illegal parameter") {
					fmt.Printf("\t%-45s [NOT SUPPORTED] %s\n", c.name, err)
				} else {
					fmt.Printf("\t%-45s [NOT SUPPORTED]\n", c.name)
				}
			} else {
				fmt.Printf("\t%-45s [OK]\n", c.name)
			}

			tlsConn.Close()
		}
	}
}
