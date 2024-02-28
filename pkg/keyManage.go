package kmipservice

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/IBM/go-kmip"
	"os"
	"time"
)

func Create(endPoint, caFile, cerFile, keyFile string) kmip.CreateResponse {
	cli := kmip.Client{}
	cli.Endpoint = endPoint
	cli.TLSConfig = &tls.Config{}
	var response kmip.CreateResponse
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		fmt.Println(err)
		return response
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
		fmt.Println(err)
		return kmip.CreateResponse{}
	}

	d, _ := json.MarshalIndent(resp, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		return response
	}
	// 激活与创建暂时放一起
	uuid := response.UniqueIdentifier
	resp, err = cli.Send(kmip.OPERATION_ACTIVATE, kmip.ActivateRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		fmt.Println(err)
		return kmip.CreateResponse{}
	}
	cli.Close()
	return response
}

// 查询key的信息
func GetKeyInfo(endPoint, caFile, cerFile, keyFile, uuid string) kmip.GetResponse {
	cli := kmip.Client{}
	cli.Endpoint = endPoint
	cli.TLSConfig = &tls.Config{}
	var response kmip.GetResponse
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		fmt.Println(err)
		return response
	}
	defer cli.Close()

	resp, err := cli.Send(kmip.OPERATION_GET, kmip.GetRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		fmt.Println(err)
		return response
	}
	d, _ := json.MarshalIndent(resp, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		return response
	}
	cli.Close()
	return response
}

// 注销秘钥
func DestroyKey(endPoint, caFile, cerFile, keyFile, uuid string) kmip.DestroyResponse {
	cli := kmip.Client{}
	cli.Endpoint = endPoint
	cli.TLSConfig = &tls.Config{}
	var response kmip.DestroyResponse
	kmip.DefaultClientTLSConfig(cli.TLSConfig)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		fmt.Println(err)
		return response
	}
	cli.TLSConfig.Certificates = []tls.Certificate{cert}
	cli.TLSConfig.RootCAs = caCertPool
	//cli.TLSConfig.InsecureSkipVerify = true
	cli.ReadTimeout = 10 * time.Second
	cli.WriteTimeout = 10 * time.Second

	err = cli.Connect()
	if err != nil {
		fmt.Println(err)
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
		fmt.Println(err)
		return response
	}

	resp2, err := cli.Send(kmip.OPERATION_DESTROY, kmip.DestroyRequest{
		UniqueIdentifier: uuid,
	})
	if err != nil {
		fmt.Println(err)
		return response
	}
	d, _ := json.MarshalIndent(resp2, "", "    ")
	err = json.Unmarshal(d, &response)
	if err != nil {
		return response
	}
	cli.Close()
	return response
}
