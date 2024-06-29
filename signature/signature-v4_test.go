package signature_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/akang943578/gofakes3/signature"
	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
)

//nolint:all
const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	iso8601Format   = "20060102T150405Z"
	yyyymmdd        = "20060102"
	unsignedPayload = "UNSIGNED-PAYLOAD"
	serviceS3       = "s3"
	SlashSeparator  = "/"
	stype           = serviceS3
)

func RandString(n int) string {
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, (n+1)/2)

	if _, err := src.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)[:n]
}

func TestSignatureMatch(t *testing.T) {

	Body := bytes.NewReader(nil)

	ak := RandString(32)
	sk := RandString(64)
	region := RandString(16)

	credentials := credentials.NewStaticCredentials(ak, sk, "")
	signature.ReloadKeys(map[string]string{ak: sk})
	signer := v4.NewSigner(credentials)

	req, err := http.NewRequest(http.MethodPost, "https://s3-endpoint.exmaple.com/bin", Body)
	if err != nil {
		t.Error(err)
	}

	_, err = signer.Sign(req, Body, serviceS3, region, time.Now())
	if err != nil {
		t.Error(err)
	}

	if result := signature.V4SignVerify(req); result != signature.ErrNone {
		t.Error(fmt.Errorf("invalid result: expect none but got %+v", signature.GetAPIError(result)))
	}
}
