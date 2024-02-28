package test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/IBM/go-kmip"
	"os"
	"testing"
	"time"
)

func TestKmipDiscovery(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.9.2.18:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	//cli.TLSConfig.RootCAs = s.certs.CAPool
	//cli.TLSConfig.Certificates = []tls.Certificate{
	//	{
	//		Certificate: [][]byte{s.certs.ClientCert.Raw},
	//		PrivateKey:  s.certs.ClientKey,
	//	},
	//}
	cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err := cli.Connect()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer cli.Close()

	versions, err := cli.DiscoverVersions(kmip.DefaultSupportedVersions)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Log("Support versions: ")
	for _, v := range versions {
		t.Log(v)
	}
	t.Log("Support versions end ")
}

func TestKmipGet(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.99.226.187:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)

	caCert, err := os.ReadFile("../assets/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("../assets/1227.pem", "../assets/1227.key")
	if err != nil {
		t.Fatal(err)
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_GET, kmip.GetRequest{
		UniqueIdentifier: "7f395fad-c550-4e54-8829-8c9666032b83",
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	t.Log(string(d))
}

func TestKmipCreate(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.99.226.187:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile("../assets/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("../assets/1227.pem", "../assets/1227.key")
	if err != nil {
		t.Fatal(err)
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_CREATE, kmip.CreateRequest{
		ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: kmip.TemplateAttribute{
			Attributes: []kmip.Attribute{
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
					Value: kmip.CRYPTO_AES,
				},
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
					Value: int32(128),
				},
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
					Value: int32(12),
				},
			},
		}})
	if err != nil {
		t.Fatalf(err.Error())
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	t.Log(string(d))
}

func TestKmipActive(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.99.226.187:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile("../assets/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("../assets/1227.pem", "../assets/1227.key")
	if err != nil {
		t.Fatal(err)
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_ACTIVATE, kmip.ActivateRequest{
		UniqueIdentifier: "d464070f-cbb1-4e8c-a858-2523a14d98a4",
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	t.Log(string(d))
}

func TestKmipDestroy(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.99.226.187:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile("../assets/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("../assets/1227.pem", "../assets/1227.key")
	if err != nil {
		t.Fatal(err)
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_DESTROY, kmip.DestroyRequest{
		UniqueIdentifier: "523d4215-0cdf-4696-b293-cbc61db7a4cf",
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	t.Log(string(d))
}

func TestKmipRevoke(t *testing.T) {
	cli := kmip.Client{}
	cli.Endpoint = "10.99.226.187:5696"
	cli.TLSConfig = &tls.Config{}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile("../assets/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("../assets/1227.pem", "../assets/1227.key")
	if err != nil {
		t.Fatal(err)
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_REVOKE, kmip.RevokeRequest{
		UniqueIdentifier: "523d4215-0cdf-4696-b293-cbc61db7a4cf",
		RevocationReason: kmip.RevocationReason{
			RevocationReasonCode: kmip.Enum(6),
			RevocationMessage:    "test",
		},
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	t.Log(string(d))
}

func ParseCertsPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	ok := false
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		// Only use PEM "CERTIFICATE" blocks without extra headers
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		ok = true
	}

	if !ok {
		return certs, errors.New("data does not contain any valid RSA or ECDSA certificates")
	}
	return certs, nil
}
