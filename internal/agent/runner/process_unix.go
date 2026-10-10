//go:build !windows

package runner

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// setProcessGroup 让 sing-box 自成进程组。
// 这样杀掉主进程时, 它派生出来的子进程也会被一起回收, 不会残留。
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup 结束整个进程组 (负 pid), 并对单进程兜底。
func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// reapStaleProcess 清理"上一次 agent 运行"遗留的孤儿 sing-box。
//
// 背景 (实测确认的缺陷): agent 被 SIGTERM 后进程直接退出, 而它启动的 sing-box
// 会被 init 收养并继续占着 2083/2053/8443/8444 端口; 新 agent 再拉起 sing-box
// 就会因端口被占而启动失败, 表现为"节点显示在线但客户端连不上"。
// 这里通过 pid 文件 + /proc/<pid>/comm 双重校验后清理, 避免误杀复用了 pid 的无关进程。
func reapStaleProcess(pidFile, exePath string) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidFile)
		return
	}

	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		_ = os.Remove(pidFile) // 进程已不存在
		return
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(string(comm))), "sing-box") {
		_ = os.Remove(pidFile) // pid 被复用, 不乱杀
		return
	}

	log.Printf("[Sing-box] 检测到上次运行遗留的孤儿内核进程 PID=%d, 正在清理以免端口占用", pid)
	killProcessGroup(pid)
	_ = os.Remove(pidFile)
}

// writePidFile 记录当前内核进程 pid (0600), 供下次启动时清理孤儿使用。
func writePidFile(pidFile string, pid int) {
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o600)
}
