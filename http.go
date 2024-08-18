package bfsp

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"runtime"

	"google.golang.org/protobuf/proto"
)

type httpClient struct {
	token   string
	baseUrl string
	https   bool
}

func NewHTTPFileServerClient(token string, baseUrl string, https bool) (FileServerClient, error) {
	return &httpClient{
		token:   token,
		baseUrl: baseUrl,
		https:   https,
	}, nil
}

func (cli *httpClient) setToken(token string) FileServerClient {
	newCli := *cli
	newCli.token = token
	return &newCli
}

func (cli *httpClient) sendFileServerMessage(msg isFileServerMessage_Message, resp proto.Message) error {
	msgBin, err := encodeFileServerMessage(msg, cli.token)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(msgBin)
	// the only two headers that the server cares about are Content-Type and Origin
	headers := map[string][]string{
		"Content-Type": {"application/octet-stream"},
		"Origin":       {"localhost:8080"},
	}
	if runtime.GOOS == "js" {
		// this header isn't actually sent to the server, but it tells the browser to send the request with CORS
		headers["js.fetch:mode"] = []string{"cors"}
	}

	scheme := "http"
	if cli.https {
		scheme = "https"
	}

	// TODO: can we use QUIC here, even in browsers? Otherwise, can we have an impl in quic and using HTTP, depending on the client
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: scheme, Host: cli.baseUrl, Path: "/api"},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
			"Origin":       {"localhost:8080"},
		},
		Body: io.NopCloser(reader),
	}

	respBin, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer respBin.Body.Close()
	body, err := io.ReadAll(respBin.Body)
	if err != nil {
		return err
	}
	// the first 4 bytes are the length of the message in uint32_le, we'll ignore that for now
	body = body[4:]

	// i <3 generics
	err = proto.Unmarshal(body, resp)
	if err != nil {
		return err
	}
	return nil
}
