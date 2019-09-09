package common

import (
	"context"
	"errors"
	"github.com/confluentinc/confluent-kafka-go/kafka"
)

func KafkaStatusCheck(host string, otherConf map[string]interface{}, kafkaType string) error {
	kafkaConfigMap := &kafka.ConfigMap{
		"bootstrap.servers": host,
	}

	for k, v := range otherConf {
		err := kafkaConfigMap.SetKey(k, v)
		if err != nil {
			return err
		}
	}

	if kafkaType == "consumer" {
		c, err := kafka.NewConsumer(kafkaConfigMap)
		if err == nil {
			_ = c.Close()
		}
		return err
	} else if kafkaType == "producer" {
		c, err := kafka.NewProducer(kafkaConfigMap)
		if err == nil {
			_ = c.Close
		}
		return err
	} else {
		return errors.New("Error KafkaType")
	}
}

func KafkaProducer(host string, topic string, upStream chan string, ctx context.Context, kafkaWorkerSize int, KafkaOtherConf map[string]interface{}) {
	for i := 0; i < kafkaWorkerSize; i++ {
		go KafkaProducerRun(host, topic, upStream, ctx, KafkaOtherConf)
	}
}

func KafkaProducerRun(host string, topic string, upStream chan string, ctx context.Context, KafkaOtherConf map[string]interface{}) {
	if KafkaOtherConf == nil {
		KafkaOtherConf = make(map[string]interface{})
	}

	kafkaConfMap := &kafka.ConfigMap{"bootstrap.servers": host}

	for k, v := range KafkaOtherConf {
		err := kafkaConfMap.SetKey(k, v)
		if err != nil {
			Logger.Error().Msg(err.Error())
		}
	}

	for {
		p, err := kafka.NewProducer(kafkaConfMap)
		if err != nil {
			Logger.Error().Msg(err.Error())
		} else {
			deliveryChan := make(chan kafka.Event)
			for {
				select {
				case <-ctx.Done():
					p.Close()
					return
				default:
					value := <-upStream
					err = p.Produce(&kafka.Message{
						TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
						Value:          []byte(value),
					}, deliveryChan)

					e := <-deliveryChan
					m := e.(*kafka.Message)

					if m.TopicPartition.Error != nil {
						Logger.Error().Err(m.TopicPartition.Error)
						p, err = kafka.NewProducer(kafkaConfMap)
						if err != nil {
							Logger.Error().Msg(err.Error())
						}
						break
					}
				}
			}
		}
	}
}
