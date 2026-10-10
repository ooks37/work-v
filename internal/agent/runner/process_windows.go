//go:build windows

package runner

import (
	"os"
	"os/exec"
)

// Windows 没有进程组语义, 但"杀进程"本身必须生效 —— 否则 Stop/重启会留下活着的内核进程,
// 本地跑测试时也会挂住等待进程退出。
func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

// Windows 不做孤儿清理 (由系统/服务管理器负责), pid 文件仅用于记录。
func reapStaleProcess(pidFile, exePath string) {}

func writePidFile(pidFile string, pid int) {}
