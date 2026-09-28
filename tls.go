package mcsoak

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

var DefaultHosts = []string{
	"de1.muterconn.com",
	"localhost",
	"127.0.0.1",
	"::1",
	"2a03:4000:62:276:780d:8eff:fe39:2a1a",
}

// GenerateSelfSignedCert generates an ECDSA P-256 certificate with 1-year validity.
func GenerateSelfSignedCert(hosts ...string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		hosts = DefaultHosts
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MCSOak Self-Signed"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return cert, nil
}

// LoadOrGenerateTLS loads certificates from disk or generates a new self-signed certificate.
func LoadOrGenerateTLS(certPath, keyPath string, hosts ...string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certPath != "" && keyPath != "" {
		if _, errCert := os.Stat(certPath); errCert == nil {
			if _, errKey := os.Stat(keyPath); errKey == nil {
				cert, err = tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					return nil, fmt.Errorf("failed to load key pair: %w", err)
				}
			}
		}
	}

	if len(cert.Certificate) == 0 {
		cert, err = GenerateSelfSignedCert(hosts...)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
