package common

import (
	"context"
	"github.com/pkg/errors"
)

var SMITH_CONF = SmithConf{}

type SmithConf struct {
	DataTransferType string

	DataChan chan string

	KafkaBootstrapServers string                 `json:"KafkaBootstrapServers"`
	KafkaTopic            string                 `json:"KafkaTopic"`
	KafkaWorkerSize       int                    `json:"KafkaWorkerSize"`
	KafkaCompression      string                 `json:"KafkaCompression"`
	KafkaOtherConf        map[string]interface{} `json:"KafkaOtherConf"`

	ctx          context.Context
	status       string
	cancelButten context.CancelFunc
}

func SmithConfInit() error {
	SMITH_CONF.DataTransferType = "kafka"
	SMITH_CONF.KafkaBootstrapServers = "10.22.73.24:9092"
	SMITH_CONF.KafkaTopic = "hids"
	SMITH_CONF.KafkaWorkerSize = 2
	SMITH_CONF.KafkaCompression = "snappy"
	SMITH_CONF.DataChan = make(chan string, 64)
	SMITH_CONF.KafkaOtherConf = make(map[string]interface{})

	err := SMITH_CONF.init()
	return err
}

func (s *SmithConf) init() error {
	if s.DataTransferType == "kafka" {
		err := KafkaStatusCheck(s.KafkaBootstrapServers, s.KafkaOtherConf, "producer")
		if err != nil {
			return err
		} else {
			ctxParent := context.Background()
			ctx, cancelButton := context.WithCancel(ctxParent)

			s.SetCtx(ctx, cancelButton)
			KafkaProducer(s.KafkaBootstrapServers, s.KafkaTopic, s.DataChan, s.ctx, s.KafkaWorkerSize, s.KafkaOtherConf)
			return nil
		}
	} else {
		return errors.New("Error DataTransferType")
	}
}

func (s *SmithConf) StopSender() {
	s.cancelButten()
}

func (s *SmithConf) SetCtx(ctx context.Context, cancelButten context.CancelFunc) {
	s.ctx = ctx
	s.cancelButten = cancelButten
}
