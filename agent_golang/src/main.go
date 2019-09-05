package main

/*
#include "c_until.c"
*/
import "C"
import (
	"fmt"
	"strings"
)

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
		m = C.GoString(C.shm_run_no_callback())
		c <- m
	}
}

func ParserExecveMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"run_path\":\"" + msg[2] + "\",\"elf\":\"" + msg[3] + "\",\"argv\":\"" + msg[4] + "\",\"pid\":\"" + msg[5] + "\",\"ppid\":\"" + msg[6] + "\",\"pgid\":\"" + msg[7] + "\",\"tgid\":\"" + msg[8] + "\",\"comm\":\"" + msg[9] + "\",\"nodename\":\"" + msg[10] + "\",\"stdin\":\"" + msg[11] + "\",\"stdout\":\"" + msg[12] + "\",\"pid_rootkit_check\":\"" + msg[13] + "\",\"file_rootkit_check\":\"" + msg[14] + "\",\"time\":\"" + msg[15] + "\"}"
	return jsonStr
}

func ParserInitMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"cwd\":\"" + msg[2] + "\",\"pid\":\"" + msg[3] + "\",\"pgid\":\"" + msg[4] + "\",\"tgid\":\"" + msg[5] + "\",\"comm\":\"" + msg[6] + "\",\"nodename\":\"" + msg[7] + "\",\"time\":\"" + msg[8] + "\"}"
	return jsonStr
}

func ParserFinitMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"cwd\":\"" + msg[2] + "\",\"pid\":\"" + msg[3] + "\",\"pgid\":\"" + msg[4] + "\",\"tgid\":\"" + msg[5] + "\",\"comm\":\"" + msg[6] + "\",\"nodename\":\"" + msg[7] + "\",\"time\":\"" + msg[8] + "\"}"
	return jsonStr
}

func ParserConnectMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"dport\":\"" + msg[4] + "\",\"dip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"sip\":\"" + msg[13] + "\",\"sport\":\"" + msg[14] + "\",\"res\":\"" + msg[15] + "\",\"pid_rootkit_check\":\"" + msg[16] + "\",\"file_rootkit_check\":\"" + msg[17] + "\",\"time\":\"" + msg[18] + "\"}"
	return jsonStr
}

func ParserAcceptMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"sport\":\"" + msg[4] + "\",\"sip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"dip\":\"" + msg[13] + "\",\"dport\":\"" + msg[14] + "\",\"res\":\"" + msg[15] + "\",\"pid_rootkit_check\":\"" + msg[16] + "\",\"file_rootkit_check\":\"" + msg[17] + "\",\"time\":\"" + msg[18] + "\"}"
	return jsonStr
}

func ParserPtraceMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"ptrace_request\":\"" + msg[2] + "\",\"target_pid\":\"" + msg[3] + "\",\"addr\":\"" + msg[4] + "\",\"data\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"res\":\"" + msg[13] + "\",\"time\":\"" + msg[14] + "\"}"
	return jsonStr
}

func ParserDNSMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"sport\":\"" + msg[4] + "\",\"sip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"dip\":\"" + msg[13] + "\",\"dport\":\"" + msg[14] + "\",\"qr\":\"" + msg[15] + "\",\"opcode\":\"" + msg[16] + "\",\"rcode\":\"" + msg[17] + "\",\"query\":\"" + msg[18] + "\",\"time\":\"" + msg[19] + "\"}"
	return jsonStr
}

func ParserCreateFileMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"elf\":\"" + msg[2] + "\",\"file_path\":\"" + msg[3] + "\",\"pid\":\"" + msg[4] + "\",\"ppid\":\"" + msg[5] + "\",\"pgid\":\"" + msg[6] + "\",\"tgid\":\"" + msg[7] + "\",\"comm\":\"" + msg[8] + "\",\"nodename\":\"" + msg[9] + "\",\"time\":\"" + msg[10] + "\"}"
	return jsonStr
}

func ParserMsg(msgChan chan string) {
	for {
		res := ""
		msg := <-msgChan
		msgList := strings.Split(msg, "\n")
		msgType := msgList[1]
		switch msgType {
		case "59":
			res = ParserExecveMsg(msgList)
		case "42":
			res = ParserConnectMsg(msgList)
		case "175":
			res = ParserInitMsg(msgList)
		case "313":
			res = ParserFinitMsg(msgList)
		case "43":
			res = ParserAcceptMsg(msgList)
		case "101":
			res = ParserPtraceMsg(msgList)
		case "601":
			res = ParserDNSMsg(msgList)
		case "602":
			res = ParserCreateFileMsg(msgList)
		}
		fmt.Println(res)
	}
}

func main() {
	msgChan := make(chan string, 1000)
	AgentInit()
	go GetMsgFromKernel(msgChan)
	ParserMsg(msgChan)
}
