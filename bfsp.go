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

const spookyDeveloperToken string = "EsABClYKATEKBnJpZ2h0cwoGZGVsZXRlCgdwYXltZW50CgV1c2FnZRgDIgkKBwgKEgMYgAgiJAoiCIEIEh06GwoCGAAKAhgBCgIYGwoDGIIICgMYgwgKAxiECBIkCAASILKiZKevm2KmYGdiG2_XbABLuxMBC4LEvF8M5Hm2L7v0GkDTIpMh20WWTwpekxyAFrWgOe4elMXMdMaJcRxuIBY6e5no4QEWDyju0164pG_H4YiJ3VQ93T1UpGHOvSiNJQcLIiIKIMTBxP9qo6d-AezifT2zDizLUJxvm2Pxga74kavuMMYg"

func ListFileMetadata(ids []string, masterKey MasterKey) (map[string]*FileMetadata, error) {
	query := FileServerMessage_ListFileMetadataQuery_{
		ListFileMetadataQuery: &FileServerMessage_ListFileMetadataQuery{
			Ids: ids,
		},
	}
	listFileMetadataResponse := ListFileMetadataResp{}
	err := sendFileServerMessage(&query, spookyDeveloperToken, &listFileMetadataResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := listFileMetadataResponse.Response.(*ListFileMetadataResp_Metadatas); ok {
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

	respErr := listFileMetadataResponse.Response.(*ListFileMetadataResp_Err)
	return nil, errors.New(respErr.Err)

}

func ListChunkMetadatas(ids []string, masterKey MasterKey) (map[string]*ChunkMetadata, error) {
	query := FileServerMessage_ListChunkMetadataQuery_{
		ListChunkMetadataQuery: &FileServerMessage_ListChunkMetadataQuery{
			Ids: ids,
		},
	}
	listChunkMetadataResponse := ListChunkMetadataResp{}
	err := sendFileServerMessage(&query, spookyDeveloperToken, &listChunkMetadataResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := listChunkMetadataResponse.Response.(*ListChunkMetadataResp_Metadatas); ok {
		return resp.Metadatas.Metadatas, nil
	}

	respErr := listChunkMetadataResponse.Response.(*ListChunkMetadataResp_Err)
	return nil, errors.New(respErr.Err)
}

func DownloadChunk(id string, fileId string, masterKey MasterKey) ([]byte, error) {
	query := FileServerMessage_DownloadChunkQuery_{
		DownloadChunkQuery: &FileServerMessage_DownloadChunkQuery{
			ChunkId: id,
		},
	}
	downloadChunkResponse := DownloadChunkResp{}
	err := sendFileServerMessage(&query, spookyDeveloperToken, &downloadChunkResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := downloadChunkResponse.Response.(*DownloadChunkResp_ChunkData_); ok {
		fileIdUUID := uuid.MustParse(fileId)
		fileIdBin, nil := fileIdUUID.MarshalBinary()

		newKeyBytes := masterKey[:]
		newKeyBytes = append(newKeyBytes, fileIdBin...)
		newKey := blake3.Sum256(newKeyBytes)

		enc, err := chacha20poly1305.NewX(newKey[:])
		var chunkBin []byte

		if err != nil {
			return chunkBin, err
		}

		compressedChunkBytes, err := enc.Open([]byte{}, resp.ChunkData.ChunkMetadata.Nonce, resp.ChunkData.Chunk, []byte(resp.ChunkData.ChunkMetadata.Id))
		if err != nil {
			return chunkBin, err
		}

		zstdDecoder, err := zstd.NewReader(bytes.NewReader(compressedChunkBytes))
		if err != nil {
			return chunkBin, err
		}
		chunkBin, err = io.ReadAll(zstdDecoder)
		if err != nil {
			return chunkBin, err
		}

		return chunkBin, nil
	}

	respErr := downloadChunkResponse.Response.(*DownloadChunkResp_Err)
	return nil, errors.New(respErr.Err)
}

func UploadFileMetadata(fileMeta *FileMetadata, masterKey MasterKey) error {
	metaBytes, err := proto.Marshal(fileMeta)
	if err != nil {
		return err
	}

	zstdEncoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	defer zstdEncoder.Close()

	compressedMetaBytes := zstdEncoder.EncodeAll(metaBytes, nil)

	uuid, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	nonce := make([]byte, 24)
	copy(nonce, uuid[:])

	newKeyBytes := masterKey[:]
	newKeyBytes = append(newKeyBytes, uuid[:]...)
	fileKey := blake3.Sum256(newKeyBytes)

	enc, err := chacha20poly1305.NewX(fileKey[:])
	if err != nil {
		return err
	}

	encryptedMetaBytes := enc.Seal(nil, nonce, compressedMetaBytes, nil)

	query := FileServerMessage_UploadFileMetadata_{
		UploadFileMetadata: &FileServerMessage_UploadFileMetadata{
			EncryptedFileMetadata: &EncryptedFileMetadata{
				Metadata: encryptedMetaBytes,
				Id:       uuid.String(),
			},
		},
	}
	uploadFileMetadataResponse := UploadFileMetadataResp{}
	err = sendFileServerMessage(&query, spookyDeveloperToken, &uploadFileMetadataResponse)
	if err != nil {
		return err
	}

	if uploadFileMetadataResponse.Err != nil {
		return errors.New(*uploadFileMetadataResponse.Err)
	}

	return nil
}

func UploadChunk(chunkMetadata *ChunkMetadata, fileUUIDStr string, encryptedCompressedChunkBytes EncryptedCompressedChunk, masterKey MasterKey) error {
	query := FileServerMessage_UploadChunk_{
		UploadChunk: &FileServerMessage_UploadChunk{
			ChunkMetadata: chunkMetadata,
			Chunk:         encryptedCompressedChunkBytes.chunk,
		},
	}
	uploadChunkResponse := UploadChunkResp{}
	err := sendFileServerMessage(&query, spookyDeveloperToken, &uploadChunkResponse)
	if err != nil {
		return err
	}

	if uploadChunkResponse.Err != nil {
		return errors.New(*uploadChunkResponse.Err)
	}

	return nil
}

func sendFileServerMessage(msg isFileServerMessage_Message, token string, resp proto.Message) error {
	msgBin, err := encodeFileServerMessage(msg, token)
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
