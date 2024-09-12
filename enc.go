package bfsp

import (
	"context"
	"encoding/base64"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const SaltString = "g8QqYqhXxwJj037KswzK3g"

type MasterKey []byte

func CreateMasterEncKey(password string) (MasterKey, error) {
	salt, err := base64.RawStdEncoding.DecodeString(SaltString)
	if err != nil {
		return nil, err
	}

	default_m_cost := 19 * 1024
	default_t_cost := 2
	default_p_cost := 1
	default_output_size := 32
	// TOOD(billy): can we ever just switch to correctly setting the output size instead of this double hash bullshit
	passwordHashArgon := argon2.IDKey([]byte(password), []byte(salt), uint32(default_t_cost), uint32(default_m_cost), uint8(default_p_cost), uint32(default_output_size))
	masterKey := blake3.Sum256(passwordHashArgon)

	return masterKey[:], nil
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

type keyContextKeyType struct{}

var keyContextKey = keyContextKeyType{}

func ContextWithMasterKey(ctx context.Context, masterKey MasterKey) context.Context {
	return context.WithValue(ctx, keyContextKey, masterKey)
}

func MasterKeyFromContext(ctx context.Context) MasterKey {
	return ctx.Value(keyContextKey).(MasterKey)
}
