package bfsp

func injectAuth(msg *FileServerMessage, token string) {
	msg.Auth = &FileServerMessage_Authentication{
		Token: token,
	}
}
