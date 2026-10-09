package collector

import (
	"runtime"
	"sync"
	"time"

	"work-v/internal/common"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type SystemCollector struct {
	mu           sync.Mutex
	lastRxBytes  uint64
	lastTxBytes  uint64
	lastSampleAt time.Time
	startTime    time.Time
}

func NewSystemCollector() *SystemCollector {
	c := &SystemCollector{
		startTime:    time.Now(),
		lastSampleAt: time.Now(),
	}
	// 初始采样网络计数
	if ioCounters, err := net.IOCounters(false); err == nil && len(ioCounters) > 0 {
		c.lastRxBytes = ioCounters[0].BytesRecv
		c.lastTxBytes = ioCounters[0].BytesSent
	}
	return c
}

// CollectStats 获取当前硬件负载与实时网络速率
func (c *SystemCollector) CollectStats(singboxPid int, singboxRunning bool) common.NodeHardwareStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var cpuPercent float64
	if cpuPercents, err := cpu.Percent(0, false); err == nil && len(cpuPercents) > 0 {
		cpuPercent = cpuPercents[0]
	}

	var memUsed, memTotal uint64
	if vm, err := mem.VirtualMemory(); err == nil {
		memUsed = vm.Used
		memTotal = vm.Total
	}

	// 计算实时瞬时速率 (Bytes/s)
	var rxRate, txRate uint64
	if ioCounters, err := net.IOCounters(false); err == nil && len(ioCounters) > 0 {
		curRx := ioCounters[0].BytesRecv
		curTx := ioCounters[0].BytesSent
		durSec := now.Sub(c.lastSampleAt).Seconds()
		if durSec > 0.1 {
			if curRx >= c.lastRxBytes {
				rxRate = uint64(float64(curRx-c.lastRxBytes) / durSec)
			}
			if curTx >= c.lastTxBytes {
				txRate = uint64(float64(curTx-c.lastTxBytes) / durSec)
			}
			c.lastRxBytes = curRx
			c.lastTxBytes = curTx
			c.lastSampleAt = now
		}
	}

	sbStatus := "stopped"
	if singboxRunning {
		sbStatus = "running"
	}

	return common.NodeHardwareStats{
		CPUPercent:    cpuPercent,
		MemUsedBytes:  memUsed,
		MemTotalBytes: memTotal,
		NetRxRate:     rxRate,
		NetTxRate:     txRate,
		SingboxStatus: sbStatus,
		SingboxPid:    singboxPid,
		UptimeSec:     uint64(time.Since(c.startTime).Seconds()),
		Version:       runtime.Version(),
	}
}
