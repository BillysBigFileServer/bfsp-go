package bfsp

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const spookyDeveloperToken string = "EsEBClcKAjE5CgZyaWdodHMKBmRlbGV0ZQoHcGF5bWVudAoFdXNhZ2UYAyIJCgcIChIDGIAIIiQKIgiBCBIdOhsKAhgACgIYAQoCGBsKAxiCCAoDGIMICgMYhAgSJAgAEiCwyxegnWquUd1RdI8oYTJR7lr-WFGB5cp9EZiBSDhhPRpAJOoVAyHElCXeZ1A2-J0-G0VYVj9QUJtY9ELcC8asSHZ8fzu-OpmXyVdR8CdDDB51fq6W5n8SNlS40sthhQQmASIiCiBCfqzP5NZUqbrLhucBcFGuRJ2Huhn8JwQ8vM7lTr0UMQ=="

func ListFileMetadata(ids []string, masterKey MasterKey) (map[string]*FileMetadata, error) {
	query := FileServerMessage_ListFileMetadataQuery_{
		ListFileMetadataQuery: &FileServerMessage_ListFileMetadataQuery{
			Ids: ids,
		},
	}
	listFileMetadataResponse, err := sendFileServerMessage[*ListFileMetadataResp](&query, spookyDeveloperToken)
	if err != nil {
		return nil, err
	}

	if resp, ok := (*listFileMetadataResponse).Response.(*ListFileMetadataResp_Metadatas); ok {
		fileMetas := map[string]*FileMetadata{}

		for _, metaInfo := range resp.Metadatas.Metadatas {
			metaId := uuid.MustParse(metaInfo.Id)
			metaIdBin, nil := metaId.MarshalBinary()

			newKeyBytes := masterKey[:]
			newKeyBytes = append(newKeyBytes, metaIdBin...)
			newKey := blake3.Sum256(newKeyBytes)

			enc, err := chacha20poly1305.NewX(newKey[:])
			if err != nil {
				return fileMetas, err
			}

			// pad nonce to 24 bytes
			metaIdBin = append(metaIdBin, make([]byte, 8)...)
			compressedMetaBytes, err := enc.Open([]byte{}, metaIdBin, metaInfo.Metadata, []byte{})
			if err != nil {
				return fileMetas, err
			}

			zstdDecoder, err := zstd.NewReader(bytes.NewReader(compressedMetaBytes))
			if err != nil {
				return fileMetas, err
			}
			metaBytes, err := io.ReadAll(zstdDecoder)
			if err != nil {
				return fileMetas, err
			}
			var fileMeta FileMetadata
			err = proto.Unmarshal(metaBytes, &fileMeta)
			if err != nil {
				return fileMetas, err
			}

			fileMetas[fileMeta.Id] = &fileMeta
		}

		return fileMetas, nil
	}

	respErr := (*listFileMetadataResponse).Response.(*ListFileMetadataResp_Err)
	return nil, errors.New(respErr.Err)

}

func sendFileServerMessage[M proto.Message](msg isFileServerMessage_Message, token string) (*M, error) {
	msgBin, err := encodeFileServerMessage(msg, token)
	if err != nil {
		return nil, err
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

	// TODO: can we use QUIC here, even in browsers? Otherwise, can we have an impl in quic and using HTTP, depending on the client
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: "http", Host: "localhost:9998", Path: "/api"},
		Header: map[string][]string{
			"Content-Type": {"application/octet-stream"},
			"Origin":       {"localhost:8080"},
		},
		Body: io.NopCloser(reader),
	}

	respBin, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer respBin.Body.Close()
	body, err := io.ReadAll(respBin.Body)
	if err != nil {
		return nil, err
	}
	// the first 4 bytes are the length of the message in uint32_le, we'll ignore that for now
	body = body[4:]

	// i <3 generics
	resp := new(M)
	err = proto.Unmarshal(body, *resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func encodeFileServerMessage(msg isFileServerMessage_Message, token string) ([]byte, error) {
	fullMessage := FileServerMessage{
		Auth: &FileServerMessage_Authentication{
			Token: token,
		},
		Message: msg,
	}
	msgBin, err := proto.Marshal(&fullMessage)
	if err != nil {
		return nil, err
	}
	return msgBin, nil
}
