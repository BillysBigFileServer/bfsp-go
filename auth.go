package bfsp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func GetDLToken(bigCentralURL string, dlToken string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	apiDLTokenURL := bigCentralURL + "/api/v1/dl_token?t=" + dlToken
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiDLTokenURL, http.NoBody)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case 404:
		case 200:
			respBin, err := io.ReadAll(resp.Body)
			if err != nil {
				return "", err
			}
			resp := string(respBin)

			return resp, nil

		default:
			return "", fmt.Errorf("status code %d from server", resp.StatusCode)
		}

		time.Sleep(1 * time.Second)
	}

}

func injectAuth(msg *FileServerMessage, token string) {
	msg.Auth = &FileServerMessage_Authentication{
		Token: token,
	}
}
