package bfsp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

func ListFileMetadata(cli FileServerClient, ids []string, masterKey MasterKey) (map[string]*FileMetadata, error) {
	query := FileServerMessage_ListFileMetadataQuery_{
		ListFileMetadataQuery: &FileServerMessage_ListFileMetadataQuery{
			Ids: ids,
		},
	}
	listFileMetadataResponse := ListFileMetadataResp{}
	err := cli.SendFileServerMessage(&query, &listFileMetadataResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := listFileMetadataResponse.Response.(*ListFileMetadataResp_Metadatas); ok {
		fileMetas := map[string]*FileMetadata{}

		for fileId, metaInfo := range resp.Metadatas.Metadatas {
			metaId := uuid.MustParse(metaInfo.Id)
			metaIdBin, err := metaId.MarshalBinary()
			if err != nil {
				return fileMetas, err
			}

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

			fileMetas[fileId] = &fileMeta
		}

		return fileMetas, nil
	}

	respErr := listFileMetadataResponse.Response.(*ListFileMetadataResp_Err)
	return nil, errors.New(respErr.Err)
}

func DownloadFileMetadata(cli FileServerClient, fileId string, masterKey MasterKey) (*FileMetadata, error) {
	query := FileServerMessage_DownloadFileMetadataQuery_{
		DownloadFileMetadataQuery: &FileServerMessage_DownloadFileMetadataQuery{
			Id: fileId,
		},
	}
	downloadFileMetadataResponse := DownloadFileMetadataResp{}
	err := cli.SendFileServerMessage(&query, &downloadFileMetadataResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := downloadFileMetadataResponse.Response.(*DownloadFileMetadataResp_EncryptedFileMetadata); ok {
		metaId := uuid.MustParse(resp.EncryptedFileMetadata.Id)
		metaIdBin, err := metaId.MarshalBinary()

		newKeyBytes := masterKey[:]
		newKeyBytes = append(newKeyBytes, metaIdBin...)
		newKey := blake3.Sum256(newKeyBytes)

		enc, err := chacha20poly1305.NewX(newKey[:])
		if err != nil {
			return nil, err
		}

		// pad nonce to 24 bytes
		metaIdBin = append(metaIdBin, make([]byte, 8)...)
		compressedMetaBytes, err := enc.Open([]byte{}, metaIdBin, resp.EncryptedFileMetadata.Metadata, []byte{})
		if err != nil {
			return nil, err
		}

		zstdDecoder, err := zstd.NewReader(bytes.NewReader(compressedMetaBytes))
		if err != nil {
			return nil, err
		}
		metaBytes, err := io.ReadAll(zstdDecoder)
		if err != nil {
			return nil, err
		}
		var fileMeta FileMetadata
		err = proto.Unmarshal(metaBytes, &fileMeta)
		if err != nil {
			return nil, err
		}

		return &fileMeta, nil
	}

	respErr := downloadFileMetadataResponse.Response.(*DownloadFileMetadataResp_Err)
	return nil, errors.New(respErr.Err)
}

type DownloadChunkArgs struct {
	ChunkID string
	FileID  string
	Token   string
}

func DownloadChunk(cli FileServerClient, args DownloadChunkArgs, masterKey MasterKey) ([]byte, error) {
	if args.Token != "" {
		cli = cli.setToken(args.Token)
	}

	query := FileServerMessage_DownloadChunkQuery_{
		DownloadChunkQuery: &FileServerMessage_DownloadChunkQuery{
			ChunkId: args.ChunkID,
		},
	}
	downloadChunkResponse := DownloadChunkResp{}
	err := cli.SendFileServerMessage(&query, &downloadChunkResponse)
	if err != nil {
		return nil, err
	}

	if resp, ok := downloadChunkResponse.Response.(*DownloadChunkResp_ChunkData_); ok {
		fileIdUUID := uuid.MustParse(args.FileID)
		fileIdBin, err := fileIdUUID.MarshalBinary()

		newKeyBytes := masterKey[:]
		newKeyBytes = append(newKeyBytes, fileIdBin...)
		newKey := blake3.Sum256(newKeyBytes)

		enc, err := chacha20poly1305.NewX(newKey[:])
		var chunkBin []byte

		if err != nil {
			return chunkBin, err
		}

		var chunkMeta *ChunkMetadata = &ChunkMetadata{}
		if resp.ChunkData.EncChunkMetadata != nil {
			encChunkMetadata := resp.ChunkData.EncChunkMetadata.EncMetadata

			nonce := make([]byte, 24)
			chunkMetaUUIDStr := resp.ChunkData.EncChunkMetadata.Id
			chunkMetaUUID, err := uuid.Parse(chunkMetaUUIDStr)
			if err != nil {
				return nil, err
			}

			copy(nonce[:16], chunkMetaUUID[:])
			compressedChunkMeta, err := enc.Open(nil, nonce, encChunkMetadata, chunkMetaUUID[:])
			if err != nil {
				return chunkBin, err
			}
			zstdDecoder, err := zstd.NewReader(nil)
			if err != nil {
				return nil, err
			}
			defer zstdDecoder.Close()

			chunkMetaBin, err := zstdDecoder.DecodeAll(compressedChunkMeta, nil)
			proto.Unmarshal(chunkMetaBin, chunkMeta)
		} else {
			chunkMeta = resp.ChunkData.ChunkMetadata
		}

		compressedChunkBytes, err := enc.Open([]byte{}, chunkMeta.Nonce, resp.ChunkData.Chunk, []byte(chunkMeta.Id))
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

		hash := blake3.Sum256(chunkBin)
		if hash != [32]byte(chunkMeta.Hash) {
			return nil, fmt.Errorf("hash does not match")
		}

		return chunkBin, nil
	}

	respErr := downloadChunkResponse.Response.(*DownloadChunkResp_Err)
	return nil, errors.New(respErr.Err)
}

func UploadFileMetadata(cli FileServerClient, fileMeta *FileMetadata, masterKey MasterKey) error {
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

	uuid, err := uuid.Parse(fileMeta.Id)
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
	err = cli.SendFileServerMessage(&query, &uploadFileMetadataResponse)
	if err != nil {
		return err
	}

	if uploadFileMetadataResponse.Err != nil {
		return errors.New(*uploadFileMetadataResponse.Err)
	}

	return nil
}

func UploadChunk(cli FileServerClient, chunkMetadata *ChunkMetadata, fileUUIDStr string, encryptedCompressedChunkBytes EncryptedCompressedChunk, masterKey MasterKey) error {
	compressedEncryptedMetaBytes, err := CompressEncryptChunkMetadata(chunkMetadata, fileUUIDStr, masterKey)
	if err != nil {
		return err
	}

	query := FileServerMessage_UploadChunk_{
		UploadChunk: &FileServerMessage_UploadChunk{
			EncChunkMetadata: &EncryptedChunkMetadata{
				Id:          chunkMetadata.Id,
				EncMetadata: compressedEncryptedMetaBytes,
			},
			Chunk: encryptedCompressedChunkBytes.chunk,
		},
	}
	uploadChunkResponse := UploadChunkResp{}
	err = cli.SendFileServerMessage(&query, &uploadChunkResponse)
	if err != nil {
		return err
	}

	if uploadChunkResponse.Err != nil {
		return errors.New(*uploadChunkResponse.Err)
	}

	return nil
}

func DeleteFileMetadata(cli FileServerClient, fileID string) error {
	query := FileServerMessage_DeleteFileMetadataQuery_{
		DeleteFileMetadataQuery: &FileServerMessage_DeleteFileMetadataQuery{
			Id: fileID,
		},
	}
	deleteFileMetadataResponse := DeleteFileMetadataResp{}
	err := cli.SendFileServerMessage(&query, &deleteFileMetadataResponse)
	if err != nil {
		return err
	}

	if deleteFileMetadataResponse.Err != nil {
		return errors.New(*deleteFileMetadataResponse.Err)
	}

	return nil
}

func DeleteChunks(cli FileServerClient, chunkIDs []string) error {
	query := FileServerMessage_DeleteChunksQuery_{
		DeleteChunksQuery: &FileServerMessage_DeleteChunksQuery{
			ChunkIds: chunkIDs,
		},
	}
	deleteChunksResponse := DeleteChunksResp{}
	err := cli.SendFileServerMessage(&query, &deleteChunksResponse)
	if err != nil {
		return err
	}

	if deleteChunksResponse.Err != nil {
		return errors.New(*deleteChunksResponse.Err)
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
	// prepend the size of the message as uint32-le
	msgLen := uint32(len(msgBin))
	fullMsgBin := make([]byte, 4+msgLen)

	binary.LittleEndian.PutUint32(fullMsgBin[:4], msgLen)
	copy(fullMsgBin[4:], msgBin)

	return fullMsgBin, nil
}
