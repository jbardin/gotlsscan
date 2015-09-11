package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

type tlsKV struct {
	name string
	val  uint16
}

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
}

func main() {
	host := flag.String("host", "", "host")
	port := flag.String("port", "443", "port")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()

	if *host == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfg := &tls.Config{
		ServerName:         *host,
		InsecureSkipVerify: *insecure,
	}

	for _, v := range versions {
		fmt.Println("Testing", v.name)
		any := false
		for _, c := range ciphers {
			cfg.MinVersion = v.val
			cfg.MaxVersion = v.val
			cfg.CipherSuites = []uint16{c.val}

			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", *host, *port))
			if err != nil {
				log.Fatal(err)
			}

			tlsConn := tls.Client(conn, cfg)
			err = tlsConn.Handshake()
			if err == nil {
				any = true
				fmt.Printf("\t%s\n", c.name)
			}

			tlsConn.Close()
		}

		if !any {
			fmt.Println("\tNOT SUPPORTED")
		}

	}
}
