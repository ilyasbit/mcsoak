package mcsoak

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var DefaultHosts = []string{
	"localhost",
	"127.0.0.1",
	"::1",
}

// BuildSANHosts collects default loopback SANs, MCSOAK_PUBLIC_IPV4/MCSOAK_PUBLIC_IPV6
// environment variables, and any caller-supplied hosts/IPs, deduplicated.
func BuildSANHosts(hosts ...string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(h string) {
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}

	for _, h := range DefaultHosts {
		add(h)
	}
	add(os.Getenv("MCSOAK_PUBLIC_IPV4"))
	add(os.Getenv("MCSOAK_PUBLIC_IPV6"))
	for _, h := range hosts {
		add(h)
	}
	return out
}

// GenerateSelfSignedCert generates an ECDSA P-256 certificate with 1-year validity.
func GenerateSelfSignedCert(hosts ...string) (tls.Certificate, error) {
	sanHosts := BuildSANHosts(hosts...)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
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

	for _, h := range sanHosts {
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
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("tls: both certPath and keyPath must be provided together")
	}

	var cert tls.Certificate
	var err error

	if certPath == "" && keyPath == "" {
		cert, err = GenerateSelfSignedCert(hosts...)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
	} else {
		cert, err = loadOrPersistCert(certPath, keyPath, hosts...)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		NextProtos: []string{"h3", "h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	return tlsConfig, nil
}

func loadOrPersistCert(certPath, keyPath string, hosts ...string) (tls.Certificate, error) {
	sanHosts := BuildSANHosts(hosts...)

	_, errCert := os.Stat(certPath)
	if errCert != nil && !os.IsNotExist(errCert) {
		return tls.Certificate{}, fmt.Errorf("failed to stat cert %q: %w", certPath, errCert)
	}
	_, errKey := os.Stat(keyPath)
	if errKey != nil && !os.IsNotExist(errKey) {
		return tls.Certificate{}, fmt.Errorf("failed to stat key %q: %w", keyPath, errKey)
	}

	if errCert == nil && errKey == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load key pair: %w", err)
		}
		leaf := cert.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to parse leaf certificate: %w", err)
			}
			cert.Leaf = leaf
		}
		if isCertValidForHosts(leaf, sanHosts) {
			return cert, nil
		}
	}

	cert, err := GenerateSelfSignedCert(hosts...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate self-signed cert: %w", err)
	}
	if err := persistCertAndKey(certPath, keyPath, cert); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func isCertValidForHosts(leaf *x509.Certificate, sanHosts []string) bool {
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter.Add(-24*time.Hour)) {
		return false
	}
	for _, h := range sanHosts {
		if ip := net.ParseIP(h); ip != nil {
			found := false
			for _, certIP := range leaf.IPAddresses {
				if certIP.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		} else {
			found := false
			for _, dns := range leaf.DNSNames {
				if strings.EqualFold(dns, h) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func persistCertAndKey(certPath, keyPath string, cert tls.Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write cert %q: %w", certPath, err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write key %q: %w", keyPath, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
