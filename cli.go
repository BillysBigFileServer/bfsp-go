package bfsp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"
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

type clientContextKeyType struct{}

var clientContextKey = clientContextKeyType{}

func ContextWithClient(ctx context.Context, cli FileServerClient) context.Context {
	return context.WithValue(ctx, clientContextKey, cli)
}

func ClientFromContext(ctx context.Context) FileServerClient {
	return ctx.Value(clientContextKey).(FileServerClient)
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

type FileInfo struct {
	Name   string
	Reader io.Reader
}

func UploadFile(ctx context.Context, fileInfo *FileInfo, concurrencyLimit int) error {
	chunks := sync.Map{}
	var totalSize uint64 = 0

	fileID, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	client := ClientFromContext(ctx)
	masterKey := MasterKeyFromContext(ctx)

	g := errgroup.Group{}
	g.SetLimit(100)
	offset := 0

UploadLoop:
	for {
		buf := make([]byte, 1024*1024)
		n, err := fileInfo.Reader.Read(buf)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				break UploadLoop
			default:
				return err
			}
		}
		buf = buf[:n]
		totalSize += uint64(n)

		g.Go(func() error {
			chunkHash := blake3.Sum256(buf)
			chunkId, err := uuid.NewRandom()
			if err != nil {
				return err
			}
			chunkLen := uint32(len(buf))

			chunkNonce := make([]byte, 24)
			// random bytes for chunk nonce
			_, err = rand.Read(chunkNonce)
			if err != nil {
				return err
			}
			chunkMetadata := &ChunkMetadata{
				Id:     chunkId.String(),
				Hash:   chunkHash[:],
				Size:   chunkLen,
				Indice: int64(offset / (1024 * 1024)),
				Nonce:  chunkNonce,
			}

			processecdChunk, err := CompressEncryptChunk(buf, chunkMetadata, fileID.String(), masterKey)
			if err != nil {
				return err
			}

			b := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(10 * time.Second))
			err = backoff.Retry(func() error {
				return UploadChunk(client, chunkMetadata, fileID.String(), *processecdChunk, masterKey)
			}, b)

			chunks.Store(uint64(chunkMetadata.Indice), chunkMetadata.Id)
			return nil
		})

		offset += 1024
	}

	if err := g.Wait(); err != nil {
		return err
	}

	chunksFileMetadata := map[uint64]string{}
	chunks.Range(func(key, value interface{}) bool {
		chunksFileMetadata[key.(uint64)] = value.(string)
		return true
	})

	currentUnixUTCTime := time.Now().UTC().Unix()
	fileMetadata := &FileMetadata{
		Id:               fileID.String(),
		Chunks:           chunksFileMetadata,
		FileName:         fileInfo.Name,
		FileType:         FileType_UNKNOWN,
		FileSize:         totalSize,
		Directory:        []string{},
		CreateTime:       currentUnixUTCTime,
		ModificationTime: currentUnixUTCTime,
	}
	err = UploadFileMetadata(client, fileMetadata, masterKey)
	if err != nil {
		return err
	}

	return nil
}

func DownloadFile(ctx context.Context, fileMeta *FileMetadata, fileWriter io.Writer, token string) error {
	client := ClientFromContext(ctx)
	masterKey := MasterKeyFromContext(ctx)

	chunkIndices := []uint64{}

	for chunkIndice := range fileMeta.Chunks {
		chunkIndices = append(chunkIndices, chunkIndice)
	}
	sort.Slice(chunkIndices, func(i, j int) bool { return chunkIndices[i] < chunkIndices[j] })

	g := errgroup.Group{}
	g.SetLimit(100)
	for _, indice := range chunkIndices {
		indice := indice
		chunkId := fileMeta.Chunks[indice]
		chunk, err := DownloadChunk(client, DownloadChunkArgs{
			ChunkID: chunkId,
			FileID:  fileMeta.Id,
			Token:   token,
		}, masterKey)
		if err != nil {
			return err
		}

		_, err = fileWriter.Write(chunk)
		if err != nil {
			return err
		}
	}
	if err := g.Wait(); err != nil {
		return err
	}

	return nil
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
