package kmipservice

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/IBM/go-kmip"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

func Create(endPoint, caFile, cerFile, keyFile, algorithm, length string) kmip.CreateResponse {
	logrus.WithFields(logrus.Fields{
		"endPoint":  endPoint,
		"caFile":    caFile,
		"cerFile":   cerFile,
		"keyFile":   keyFile,
		"algorithm": algorithm,
		"length":    length,
	}).Info("Create key.")
	var response kmip.CreateResponse
	cli, err, hasError := getClient(endPoint, caFile, cerFile, keyFile)
	if hasError {
		return response
	}

	err = cli.Connect()
	if err != nil {
		logrus.Error("failed to connect server. ", err)
		return response
	}
	defer cli.Close()

	var keyAlgorithm kmip.Enum
	var keyLength int32

	switch algorithm {
	case "AES":
		keyAlgorithm = kmip.CRYPTO_AES
	case "SM4":
		keyAlgorithm = kmip.CRYPTO_SM4
	default:
		keyAlgorithm = kmip.CRYPTO_AES
	}

	switch length {
	case "128":
		keyLength = int32(128)
	case "192":
		keyLength = int32(192)
	case "256":
		keyLength = int32(256)
	default:
		keyLength = int32(256)
	}

	resp, err := cli.Send(kmip.OPERATION_CREATE, kmip.CreateRequest{
		ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: kmip.TemplateAttribute{
			Attributes: []kmip.Attribute{
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
					Value: keyAlgorithm,
				},
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
					Value: keyLength,
				},
				{
					Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
					Value: int32(12),
				},
			},
		}})
	if err != nil {
		logrus.Error("failed to send create request. ", err)
		return kmip.CreateResponse{}
	}

	d, _ := json.MarshalIndent(resp, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		logrus.Error("failed to create key. ", err)
		return response
	}
	// 激活与创建暂时放一起
	uuid := response.UniqueIdentifier
	resp, err = cli.Send(kmip.OPERATION_ACTIVATE, kmip.ActivateRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		logrus.Error("failed to send activate request. ", err)
		return kmip.CreateResponse{}
	}
	logrus.Info("Create success, key uuid is ", uuid)
	err = cli.Close()
	if err != nil {
		logrus.Error("failed to close connect. ", err)
	}
	return response
}

// GetKeyInfo 查询key的信息
func GetKeyInfo(endPoint, caFile, cerFile, keyFile, uuid string) kmip.GetResponse {
	logrus.WithFields(logrus.Fields{
		"endPoint": endPoint,
		"caFile":   caFile,
		"cerFile":  cerFile,
		"keyFile":  keyFile,
		"uuid":     uuid,
	}).Info("Query key.")
	var response kmip.GetResponse
	cli, err, hasError := getClient(endPoint, caFile, cerFile, keyFile)
	if hasError {
		return response
	}
	err = cli.Connect()
	if err != nil {
		logrus.Error("failed to connect server. ", err)
		return response
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_GET, kmip.GetRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		logrus.Error("failed to send query request. ", err)
		return response
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		logrus.Error("failed to close connect. ", err)
	}
	logrus.Info("Query success, key uuid is ", response.UniqueIdentifier)
	return response
}

// 注销秘钥
func DestroyKey(endPoint, caFile, cerFile, keyFile, uuid string) kmip.DestroyResponse {
	logrus.WithFields(logrus.Fields{
		"endPoint": endPoint,
		"caFile":   caFile,
		"cerFile":  cerFile,
		"keyFile":  keyFile,
		"uuid":     uuid,
	}).Info("Destroy key.")
	var response kmip.DestroyResponse
	cli := kmip.Client{}
	cli.Endpoint = endPoint
	cli.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	cli, err, hasError := getClient(endPoint, caFile, cerFile, keyFile)
	if hasError {
		return response
	}

	err = cli.Connect()
	if err != nil {
		logrus.Error("failed to connect server. ", err)
		return response
	}
	defer cli.Close()

	// destroy之前需要先revoke，这里临时放到一起
	_, err = cli.Send(kmip.OPERATION_REVOKE, kmip.RevokeRequest{
		UniqueIdentifier: uuid,
		RevocationReason: kmip.RevocationReason{
			RevocationReasonCode: kmip.Enum(6),
			RevocationMessage:    "disable",
		},
	})
	if err != nil {
		logrus.Error("failed to revoke key. ", err)
		return response
	}

	resp2, err := cli.Send(kmip.OPERATION_DESTROY, kmip.DestroyRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		logrus.Error("failed to destroy key. ", err)
		return response
	}
	d, _ := json.MarshalIndent(resp2, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		return response
	}
	logrus.Info("Destroy success, key uuid is ", response.UniqueIdentifier)
	cli.Close()
	return response
}

func getClient(endPoint string, caFile string, cerFile string, keyFile string) (kmip.Client, error, bool) {
	cli := kmip.Client{}
	cli.Endpoint = endPoint
	cli.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		logrus.Error("failed to read ca file. ", err)
		return kmip.Client{}, nil, true
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		logrus.Error("failed to load key pair. ", err)
		return kmip.Client{}, nil, true
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second
	return cli, err, false
}
