package bfsp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type encTokenInfo struct {
	Token        string `json:"token"`
	EncMasterKey string `json:"encrypted_master_key"`
}

type TokenInfo struct {
	Token     string
	MasterKey MasterKey
}

func GetToken(bigCentralURL string, dlToken string, rsaPrivKey *rsa.PrivateKey) (*TokenInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	apiDLTokenURL := bigCentralURL + "/api/v1/dl_token?t=" + dlToken
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiDLTokenURL, http.NoBody)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case 404:
		case 200:
			var encryptedDLTokenInfo encTokenInfo
			decoder := json.NewDecoder(resp.Body)
			decoder.Decode(&encryptedDLTokenInfo)
			encMasterKeyBin, err := base64.URLEncoding.DecodeString(encryptedDLTokenInfo.EncMasterKey)
			if err != nil {
				return nil, err
			}
			masterKey, err := rsaPrivKey.Decrypt(rand.Reader, encMasterKeyBin, nil)
			if err != nil {
				return nil, err
			}

			return &TokenInfo{
				Token:     encryptedDLTokenInfo.Token,
				MasterKey: masterKey,
			}, nil

		default:
			return nil, fmt.Errorf("status code %d from server", resp.StatusCode)
		}

		time.Sleep(1 * time.Second)
	}

}

func injectAuth(msg *FileServerMessage, token string) {
	msg.Auth = &FileServerMessage_Authentication{
		Token: token,
	}
}
