package main

/*
#include "c_until.c"
*/
import "C"
import (
	"github.com/EBWi11/AgentSmith-HIDS/agent_golang/common"
	"github.com/panjf2000/ants"
	"github.com/sevlyar/go-daemon"
	"os"
	"strconv"
	"strings"
)

var GlobalCache = common.GetGlobalCache()

func AgentInit() {
	C.init()
	C.shm_init()

	if GlobalCache == nil {
		AgentClose()
		common.Logger.Error().Msg("Global Cache Init Error")
		os.Exit(1)
	}
	common.Logger.Info().Msg("AgentSmith-HIDS Start")
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

func GetUserNameByUid(uid string) (string, error) {
	uidTmp, err := strconv.Atoi(uid)
	if err != nil {
		return "", err
	}

	return C.GoString(C.get_user(C.uid_t(uidTmp))), nil
}

func GetELFMD5(elf string) string {
	elfmd5 := ""
	elfMd5Cache, err := GlobalCache.Get(elf)

	if elfMd5Cache == nil {
		elfmd5 = common.GetFileMD5(elf)
		err = GlobalCache.Set(elf, []byte(elfmd5))
		if err != nil {
			common.Logger.Error().Msg(err.Error())
		}
	} else {
		elfmd5 = string(elfMd5Cache)
	}

	return elfmd5
}

func ParserMsgWorker(oriMsg string) {
	res := ""
	userNmae := ""
	elfmd5 := ""
	hostName := ""

	hostNameCache, err := GlobalCache.Get("#HOSTNAME")

	if hostNameCache != nil {
		hostName = string(hostNameCache)
	} else {
		hostName = common.GetHostName()
		err = GlobalCache.Set("#HOSTNAME", []byte(hostName))
		if err != nil {
			common.Logger.Error().Msg(err.Error())
		}
	}

	msgList := strings.Split(oriMsg, "\n")

	msgType := msgList[1]
	uidStr := msgList[0]

	cacheRes, err := GlobalCache.Get(uidStr)

	if cacheRes == nil {
		userNmae, err = GetUserNameByUid(uidStr)
		if err != nil {
			common.Logger.Error().Msg(err.Error())
		}

		err = GlobalCache.Set(uidStr, []byte(userNmae))
		if err != nil {
			common.Logger.Error().Msg(err.Error())
		}
	} else {
		userNmae = string(cacheRes)
	}

	msgList = append(msgList, userNmae)
	msgList = append(msgList, hostName)

	switch msgType {
	case "59":
		elfmd5 = GetELFMD5(msgList[3])
		msgList = append(msgList, elfmd5)
		res = ParserExecveMsg(msgList)
	case "42":
		elfmd5 = GetELFMD5(msgList[6])
		msgList = append(msgList, elfmd5)
		res = ParserConnectMsg(msgList)
	case "175":
		elfmd5 = "-1"
		res = ParserInitMsg(msgList)
	case "313":
		elfmd5 = "-1"
		res = ParserFinitMsg(msgList)
	case "43":
		elfmd5 = GetELFMD5(msgList[6])
		msgList = append(msgList, elfmd5)
		res = ParserAcceptMsg(msgList)
	case "101":
		elfmd5 = GetELFMD5(msgList[6])
		msgList = append(msgList, elfmd5)
		res = ParserPtraceMsg(msgList)
	case "601":
		elfmd5 = GetELFMD5(msgList[6])
		msgList = append(msgList, elfmd5)
		res = ParserDNSMsg(msgList)
	case "602":
		elfmd5 = GetELFMD5(msgList[2])
		msgList = append(msgList, elfmd5)
		res = ParserCreateFileMsg(msgList)
	}
	common.SMITH_CONF.DataChan <- res
}

func ParserMsg(msgChan chan string, p *ants.Pool) {
	for {
		msg := <-msgChan
		err := p.Submit(
			func() {
				ParserMsgWorker(msg)
			})

		if err != nil {
			common.Logger.Error().Msg(err.Error())
		}
	}
}

func ParserExecveMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"run_path\":\"" + msg[2] + "\",\"elf\":\"" + msg[3] + "\",\"argv\":\"" + msg[4] + "\",\"pid\":\"" + msg[5] + "\",\"ppid\":\"" + msg[6] + "\",\"pgid\":\"" + msg[7] + "\",\"tgid\":\"" + msg[8] + "\",\"comm\":\"" + msg[9] + "\",\"nodename\":\"" + msg[10] + "\",\"stdin\":\"" + msg[11] + "\",\"stdout\":\"" + msg[12] + "\",\"pid_rootkit_check\":\"" + msg[13] + "\",\"file_rootkit_check\":\"" + msg[14] + "\",\"sessionid\":\"" + msg[15] + "\",\"time\":\"" + msg[16] + "\",\"user\":\"" + msg[17] + "\",\"hostname\":\"" + msg[18] + "\",\"elf_md5\":\"" + msg[19] + "\"}"
	return jsonStr
}

func ParserInitMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"cwd\":\"" + msg[2] + "\",\"pid\":\"" + msg[3] + "\",\"pgid\":\"" + msg[4] + "\",\"tgid\":\"" + msg[5] + "\",\"comm\":\"" + msg[6] + "\",\"nodename\":\"" + msg[7] + "\",\"sessionid\":\"" + msg[8] + "\",\"time\":\"" + msg[9] + "\",\"user\":\"" + msg[10] + "\",\"hostname\":\"" + msg[11] + "\",\"elf_md5\":\"" + msg[12] + "\"}"
	return jsonStr
}

func ParserFinitMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"cwd\":\"" + msg[2] + "\",\"pid\":\"" + msg[3] + "\",\"pgid\":\"" + msg[4] + "\",\"tgid\":\"" + msg[5] + "\",\"comm\":\"" + msg[6] + "\",\"nodename\":\"" + msg[7] + "\",\"sessionid\":\"" + msg[8] + "\",\"time\":\"" + msg[9] + "\",\"user\":\"" + msg[10] + "\",\"hostname\":\"" + msg[11] + "\",\"elf_md5\":\"" + msg[12] + "\"}"
	return jsonStr
}

func ParserConnectMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"dport\":\"" + msg[4] + "\",\"dip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"sip\":\"" + msg[13] + "\",\"sport\":\"" + msg[14] + "\",\"res\":\"" + msg[15] + "\",\"pid_rootkit_check\":\"" + msg[16] + "\",\"file_rootkit_check\":\"" + msg[17] + "\",\"sessionid\":\"" + msg[18] + "\",\"time\":\"" + msg[19] + "\",\"user\":\"" + msg[20] + "\",\"hostname\":\"" + msg[21] + "\",\"elf_md5\":\"" + msg[22] + "\"}"
	return jsonStr
}

func ParserAcceptMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"sport\":\"" + msg[4] + "\",\"sip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"dip\":\"" + msg[13] + "\",\"dport\":\"" + msg[14] + "\",\"res\":\"" + msg[15] + "\",\"pid_rootkit_check\":\"" + msg[16] + "\",\"file_rootkit_check\":\"" + msg[17] + "\",\"sessionid\":\"" + msg[18] + "\",\"time\":\"" + msg[19] + "\",\"user\":\"" + msg[20] + "\",\"hostname\":\"" + msg[21] + "\",\"elf_md5\":\"" + msg[22] + "\"}"
	return jsonStr
}

func ParserPtraceMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"ptrace_request\":\"" + msg[2] + "\",\"target_pid\":\"" + msg[3] + "\",\"addr\":\"" + msg[4] + "\",\"data\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"res\":\"" + msg[13] + "\",\"sessionid\":\"" + msg[14] + "\",\"time\":\"" + msg[15] + "\",\"user\":\"" + msg[16] + "\",\"hostname\":\"" + msg[17] + "\",\"elf_md5\":\"" + msg[18] + "\"}"
	return jsonStr
}

func ParserDNSMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"sa_family\":\"" + msg[2] + "\",\"fd\":\"" + msg[3] + "\",\"sport\":\"" + msg[4] + "\",\"sip\":\"" + msg[5] + "\",\"elf\":\"" + msg[6] + "\",\"pid\":\"" + msg[7] + "\",\"ppid\":\"" + msg[8] + "\",\"pgid\":\"" + msg[9] + "\",\"tgid\":\"" + msg[10] + "\",\"comm\":\"" + msg[11] + "\",\"nodename\":\"" + msg[12] + "\",\"dip\":\"" + msg[13] + "\",\"dport\":\"" + msg[14] + "\",\"qr\":\"" + msg[15] + "\",\"opcode\":\"" + msg[16] + "\",\"rcode\":\"" + msg[17] + "\",\"query\":\"" + msg[18] + "\",\"sessionid\":\"" + msg[19] + "\",\"time\":\"" + msg[20] + "\",\"user\":\"" + msg[21] + "\",\"hostname\":\"" + msg[22] + "\",\"elf_md5\":\"" + msg[23] + "\"}"
	return jsonStr
}

func ParserCreateFileMsg(msg []string) string {
	jsonStr := "{\"uid\":\"" + msg[0] + "\",\"syscall\":\"" + msg[1] + "\",\"elf\":\"" + msg[2] + "\",\"file_path\":\"" + msg[3] + "\",\"pid\":\"" + msg[4] + "\",\"ppid\":\"" + msg[5] + "\",\"pgid\":\"" + msg[6] + "\",\"tgid\":\"" + msg[7] + "\",\"comm\":\"" + msg[8] + "\",\"nodename\":\"" + msg[9] + "\",\"sessionid\":\"" + msg[10] + "\",\"time\":\"" + msg[11] + "\",\"user\":\"" + msg[12] + "\",\"hostname\":\"" + msg[13] + "\",\"elf_md5\":\"" + msg[14] + "\"}"
	return jsonStr
}

func Run() {
	msgChan := make(chan string, 128)
	AgentInit()
	pool, err := ants.NewPool(4)
	if err != nil {
		common.Logger.Error().Msg(err.Error())
		AgentClose()
	}

	go GetMsgFromKernel(msgChan)
	ParserMsg(msgChan, pool)
}

func main() {
	common.LogInit()
	err := common.SmithConfInit()

	if err != nil {
		common.Logger.Error().Msg(err.Error())
		return
	}

	cntxt := &daemon.Context{
		PidFilePerm: 0644,
		PidFileName: "/var/run/smith_hids.pid",
		LogFileName: "/var/log/smith_hids.log",
		LogFilePerm: 0640,
		WorkDir:     "/",
		Umask:       027,
		Args:        nil,
	}

	d, err := cntxt.Reborn()

	if err != nil {
		common.Logger.Error().Msg(err.Error())
		return
	}

	if d != nil {
		return
	}

	defer cntxt.Release()

	go Run()

	err = daemon.ServeSignals()
	if err != nil {
		common.Logger.Error().Msg(err.Error())
	}
}
