package common

import (
	"github.com/rs/zerolog"
	"os"
)

var Logger = LogInit()

func LogInit() zerolog.Logger {
	logFile, _ := os.OpenFile("/var/log/smith_hids.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	log := zerolog.New(logFile).With().Caller().Timestamp().Logger()
	return log
}
