package bfsp

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type FileServerClient interface {
	sendFileServerMessage(msg isFileServerMessage_Message, resp proto.Message) error
	setToken(token string) FileServerClient
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

func ShareFile(fileMeta *FileMetadata, tokenStr string, masterKey MasterKey) (*ViewFileInfo, error) {
	fileUUID := uuid.MustParse(fileMeta.Id)
	fileUUIDBin, err := fileUUID.MarshalBinary()
	if err != nil {
		return nil, err
	}

	tokenBytes, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}

	token, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		return nil, err
	}

	blockBuilder := token.CreateBlock()

	// check all is currently unsupported in biscuit-go, gotta use a few check ifs rn
	check, err := parser.FromStringCheck(`check if rights($rights), right($right), $rights.contains($right)`)
	if err != nil {
		return nil, err
	}
	err = blockBuilder.AddCheck(check)
	if err != nil {
		return nil, err
	}

	check, err = parser.FromStringCheck(`check if allowed_file_ids($allowed_file_ids), file_ids($file_ids), $allowed_file_ids.contains($file_ids)`)
	if err != nil {
		return nil, err
	}
	err = blockBuilder.AddCheck(check)
	if err != nil {
		return nil, err
	}

	blockBuilder.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "rights",
			IDs: []biscuit.Term{
				biscuit.Set{biscuit.String("read"), biscuit.String("write")},
			},
		},
	})
	blockBuilder.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "allowed_file_ids",
			IDs: []biscuit.Term{
				biscuit.Set{biscuit.String(fileUUID.String())},
			},
		},
	})
	rng := rand.Reader
	newToken, err := token.Append(rng, blockBuilder.Build())
	if err != nil {
		return nil, err
	}

	fileKeyBytes := masterKey[:]
	fileKeyBytes = append(fileKeyBytes, fileUUIDBin...)
	fileKey := blake3.Sum256(fileKeyBytes)

	serializedToken, err := newToken.Serialize()
	if err != nil {
		return nil, err
	}
	serializedTokenStr := base64.URLEncoding.EncodeToString(serializedToken)

	return &ViewFileInfo{
		Id:         fileMeta.Id,
		Token:      serializedTokenStr,
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
