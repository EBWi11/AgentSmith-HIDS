package common

import (
	"github.com/rs/zerolog"
	"os"
)

var Logger = zerolog.Logger{}

func LogInit() {
	logFile, _ := os.OpenFile("/var/log/smith_hids.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	Logger = zerolog.New(logFile).With().Caller().Timestamp().Logger()
}
