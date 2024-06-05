package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

var (
	host  = flag.String("host", "https://localhost:8090", "Host address of Cloud Signature Service")
	token = flag.String("token", "", "Token for accessing Cloud Signature Service")
	index = flag.Int("index", 0, "Index of the credential to be selected")
	pin   = flag.String("pin", "", "PIN of the credential to use")
)

func request(url string, ctx []byte, ctyp, tok string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(ctx))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ctyp)
	req.Header.Set("Authorization", "Bearer "+tok)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid response: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func main() {
	flag.Parse()

	ctx, err := request(*host+"/csc/v1/info", []byte("{}"), "application/json", *token)
	if err != nil {
		panic(err)
	}

	fmt.Printf("1. ==> info:%s\n", ctx)

	ctx, err = request(*host+"/csc/v1/credentials/list", []byte("{}"), "application/json", *token)
	if err != nil {
		panic(err)
	}

	// 凭据列表
	fmt.Printf("2. ==> credential list:%s\n", ctx)

	var credList struct {
		CredentialIDs []string `json:"credentialIDs"`
	}

	err = json.Unmarshal(ctx, &credList)
	if err != nil {
		panic(err)
	}

	if len(credList.CredentialIDs) == 0 {
		panic("no credentials")
	}

	credID := credList.CredentialIDs[*index]

	ctx, err = json.Marshal(struct {
		CredentialID string `json:"credentialID"`
		Certificates string `json:"certificates"`
		CertInfo     bool   `json:"certInfo"`
		AuthInfo     bool   `json:"authInfo"`
	}{
		CredentialID: credID,
		Certificates: "single",
		CertInfo:     true,
		AuthInfo:     true,
	})
	if err != nil {
		panic(err)
	}

	ctx, err = request(*host+"/csc/v1/credentials/info", ctx, "application/json", *token)
	if err != nil {
		panic(err)
	}

	// 凭据详情
	fmt.Printf("3. ==> credential info: %s\n", ctx)

	// 凭据中的证书
	var credInfo struct {
		CredentialID string `json:"credentialID"`
		Key          struct {
			Status string   `json:"status"`
			Algo   []string `json:"algo"`
			Len    int      `json:"len"`
		} `json:"key"`
		Cert struct {
			Status       string   `json:"status"`
			Certificates []string `json:"certificates"`
		} `json:"cert"`
		AuthMode string `json:"authMode"`
	}

	err = json.Unmarshal(ctx, &credInfo)
	if err != nil {
		panic(err)
	}

	// 显示KEY信息
	fmt.Printf("4. ==> key info: %+v\n", credInfo.Key)

	if len(credInfo.Cert.Certificates) == 0 {
		panic("no certificates")
	}

	ctx, err = base64.StdEncoding.DecodeString(credInfo.Cert.Certificates[0])
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(ctx)
	if err != nil {
		panic(err)
	}

	// 显示证书信息
	fmt.Printf("5. ==> certificate info: %s\n", cert.Subject.CommonName)

	// 证书中的公钥信息
	pubKey := cert.PublicKey.(*rsa.PublicKey)

	str := uuid.NewString()

	// 原始消息
	fmt.Printf("6. ==> original message: %s\n", str)

	hash := sha256.Sum256([]byte(str))

	// 哈希消息
	fmt.Printf("7. ==> hashed message: %v\n", hash)

	ctx, err = json.Marshal(struct {
		CredentialID  string   `json:"credentialID"`
		NumSignatures int      `json:"numSignatures"`
		Hash          []string `json:"hash"`
		Pin           string   `json:"PIN"`
	}{
		CredentialID:  credID,
		NumSignatures: 1,
		Hash: []string{
			base64.StdEncoding.EncodeToString(hash[:]),
		},
		Pin: *pin,
	})
	if err != nil {
		panic(err)
	}

	ctx, err = request(*host+"/csc/v1/credentials/authorize", ctx, "application/json", *token)
	if err != nil {
		panic(err)
	}

	// SAD
	fmt.Printf("8. ==> SAD: %s\n", ctx)

	var credAuth struct {
		SAD       string `json:"SAD"`
		ExpiresIn int    `json:"expiresIn"`
	}
	err = json.Unmarshal(ctx, &credAuth)
	if err != nil {
		panic(err)
	}

	ctx, err = json.Marshal(struct {
		CredentialID string   `json:"credentialID"`
		SAD          string   `json:"SAD"`
		Hash         []string `json:"hash"`
		HashAlgo     string   `json:"hashAlgo"`
		SignAlgo     string   `json:"signAlgo"`
	}{
		CredentialID: credID,
		SAD:          credAuth.SAD,
		Hash: []string{
			base64.StdEncoding.EncodeToString(hash[:]),
		},
		HashAlgo: "2.16.840.1.101.3.4.2.1",
		SignAlgo: credInfo.Key.Algo[0],
	})
	if err != nil {
		panic(err)
	}

	ctx, err = request(*host+"/csc/v1/signatures/signHash", ctx, "application/json", *token)
	if err != nil {
		panic(err)
	}

	// 签名
	fmt.Printf("9. ==> signature: %s\n", ctx)

	// 验签
	var signInfo struct {
		Signatures []string `json:"signatures"`
	}
	err = json.Unmarshal(ctx, &signInfo)
	if err != nil {
		panic(err)
	}

	if len(signInfo.Signatures) == 0 {
		panic("no signatures")
	}

	ctx, err = base64.StdEncoding.DecodeString(signInfo.Signatures[0])
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], ctx)
	if err != nil {
		panic(err)
	}

	// 验签通过
	fmt.Printf("10. ==> signature verified\n")
}
