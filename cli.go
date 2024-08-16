package bfsp

import (
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

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
