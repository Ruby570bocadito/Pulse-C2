package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// MTLSConfig holds mutual TLS configuration.
type MTLSConfig struct {
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	ServerCert *tls.Certificate
}

// GenerateCA creates a new Certificate Authority.
func GenerateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "BTY C2 CA",
			Organization: []string{"BTY"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return cert, key, nil
}

// GenerateServerCert creates a server certificate signed by the CA.
func GenerateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"BTY C2"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "localhost"},
		IPAddresses: nil,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM, _ := x509.MarshalECPrivateKey(key)
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	tlsCert, err := tls.X509KeyPair(certPEM, keyBlock)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}

	return &tlsCert, nil
}

// GenerateAgentCert creates an agent (client) certificate signed by the CA.
func GenerateAgentCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, agentID string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"BTY Agent"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create agent cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM, _ := x509.MarshalECPrivateKey(key)
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	tlsCert, err := tls.X509KeyPair(certPEM, keyBlock)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}

	return &tlsCert, nil
}

// NewMTLSServerConfig creates a TLS config that requires client certificates.
func NewMTLSServerConfig(serverCert tls.Certificate, caCert *x509.Certificate) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// NewMTLSClientConfig creates a TLS config with client certificate for mTLS.
func NewMTLSClientConfig(clientCert tls.Certificate, caCert *x509.Certificate, serverName string) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}
}

// ExportPEM exports a certificate and key to PEM format.
func ExportPEM(cert *x509.Certificate, key *ecdsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	if cert == nil {
		return nil, nil, fmt.Errorf("empty certificate")
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	if key != nil {
		keyPEMBytes, _ := x509.MarshalECPrivateKey(key)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEMBytes})
	}

	return certPEM, keyPEM, nil
}
