package common

/*
#include "c_until.c"
*/
import "C"

func AgentInit() {
	C.init()
	C.shm_init()
}

func AgentClose() {
	C.shm_close()
}

func GetMsgFromKernel(c chan string) {
	m := ""
	for {
		m = C.shm_run_no_callback()
		c <- m
	}
}
