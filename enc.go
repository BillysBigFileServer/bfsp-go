package bfsp

import (
	"encoding/base64"

	"golang.org/x/crypto/argon2"
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
