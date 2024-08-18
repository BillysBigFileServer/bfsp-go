package bfsp

import (
	"encoding/base64"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type FileServerClient interface {
	sendFileServerMessage(msg isFileServerMessage_Message, resp proto.Message) error
}

type EncryptedCompressedChunk struct {
	chunk []byte
}

func CompressEncryptChunk(chunkBytes []byte, chunkMetadata *ChunkMetadata, fileId string, masterKey MasterKey) (*EncryptedCompressedChunk, error) {
	zstdEncoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer zstdEncoder.Close()

	compressedChunkBytes := zstdEncoder.EncodeAll(chunkBytes, nil)

	fileUUID := uuid.MustParse(fileId)
	fileUUIDBin, err := fileUUID.MarshalBinary()
	fileKeyBytes := masterKey[:]
	fileKeyBytes = append(fileKeyBytes, fileUUIDBin...)
	fileKey := blake3.Sum256(fileKeyBytes)

	enc, err := chacha20poly1305.NewX(fileKey[:])
	if err != nil {
		return nil, err
	}
	encryptedChunkBytes := enc.Seal(nil, chunkMetadata.Nonce, compressedChunkBytes, []byte(chunkMetadata.Id))

	return &EncryptedCompressedChunk{
		chunk: encryptedChunkBytes,
	}, nil
}

func CompressEncryptChunkMetadata(chunkMetadata *ChunkMetadata, fileId string, masterKey MasterKey) ([]byte, error) {
	zstdEncoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer zstdEncoder.Close()

	b, err := proto.Marshal(chunkMetadata)
	compressedChunkBytes := zstdEncoder.EncodeAll(b, nil)

	fileUUID := uuid.MustParse(fileId)
	fileUUIDBin, err := fileUUID.MarshalBinary()
	fileKeyBytes := masterKey[:]
	fileKeyBytes = append(fileKeyBytes, fileUUIDBin...)
	fileKey := blake3.Sum256(fileKeyBytes)

	enc, err := chacha20poly1305.NewX(fileKey[:])
	if err != nil {
		return nil, err
	}
	chunkMetaUUID, err := uuid.Parse(chunkMetadata.Id)
	if err != nil {
		return nil, err
	}
	nonce, err := chunkMetaUUID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nonce = append(nonce, make([]byte, 24-len(nonce))...)

	encryptedChunkMetaBytes := enc.Seal(nil, nonce, compressedChunkBytes, chunkMetaUUID[:])
	return encryptedChunkMetaBytes, nil
}

func ShareFile(fileMeta *FileMetadata, token string, masterKey MasterKey) (*ViewFileInfo, error) {
	fileUUID := uuid.MustParse(fileMeta.Id)
	fileUUIDBin, err := fileUUID.MarshalBinary()
	if err != nil {
		return nil, err
	}

	fileKeyBytes := masterKey[:]
	fileKeyBytes = append(fileKeyBytes, fileUUIDBin...)
	fileKey := blake3.Sum256(fileKeyBytes)

	return &ViewFileInfo{
		Id:         fileMeta.Id,
		Token:      token,
		FileEncKey: base64.URLEncoding.EncodeToString(fileKey[:]),
	}, nil
}

func EncodeViewFileInfo(view *ViewFileInfo) (string, error) {
	bin, err := proto.Marshal(view)
	if err != nil {
		return "", err
	}

	zstdEncoder, err := zstd.NewWriter(nil)
	if err != nil {
		return "", err
	}
	defer zstdEncoder.Close()

	compressedViewBytes := zstdEncoder.EncodeAll(bin, nil)
	viewInfoB64 := base64.URLEncoding.EncodeToString(compressedViewBytes)

	return viewInfoB64, nil
}

func DecodeViewFileInfoB64(b64 string) (*ViewFileInfo, error) {
	compressedViewInfoBin, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	zstdDecoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer zstdDecoder.Close()

	viewInfoBytes, err := zstdDecoder.DecodeAll(compressedViewInfoBin, nil)
	if err != nil {
		return nil, err
	}

	var viewFileInfo ViewFileInfo
	err = proto.Unmarshal(viewInfoBytes, &viewFileInfo)
	if err != nil {
		return nil, err
	}

	return &viewFileInfo, nil
}
