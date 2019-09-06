package common

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

func GetHostName() string {
	hostName, err := os.Hostname()
	if err != nil {
		Logger.Error().Err(err)
	}
	return hostName
}

func GetFileMD5(path string) string {
	f, err := os.Open(path)
	if err != nil {
		if f != nil {
			_ = f.Close()
		}
		return ""
	}

	md5hash := md5.New()
	if _, err := io.Copy(md5hash, f); err != nil {
		if f != nil {
			_ = f.Close()
		}
		return ""
	}

	md5str := fmt.Sprintf("%x", md5hash.Sum(nil))
	_ = f.Close()

	return md5str
}
