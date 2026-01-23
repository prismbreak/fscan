package Core

import "github.com/shadow1ng/fscan/Common"

// Scan 执行整体扫描流程
func Scan(info Common.HostInfo) {
	Common.LogBase("开始信息扫描")
	strategy := NewServiceScanStrategy()
	strategy.Execute(info)
	Common.LogBase("扫描已完成")
}
