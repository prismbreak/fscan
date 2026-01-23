package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
)

// ServiceScanStrategy 服务扫描策略
type ServiceScanStrategy struct{}

// NewServiceScanStrategy 创建新的服务扫描策略
func NewServiceScanStrategy() *ServiceScanStrategy {
	return &ServiceScanStrategy{}
}

// Execute 执行服务扫描策略
func (s *ServiceScanStrategy) Execute(info Common.HostInfo) {
	// 验证扫描目标
	if info.Host == "" {
		Common.LogError("未指定扫描目标")
		return
	}

	// 解析目标主机
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
		return
	}

	Common.LogBase("开始主机扫描")

	// 主机存活性检测和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		if s.shouldPerformLivenessCheck(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogBase(fmt.Sprintf("存活主机数量: %d", len(hosts)))
		}

		// 端口扫描与JDWP探测
		s.discoverAlivePorts(hosts)
	}
}

// shouldPerformLivenessCheck 判断是否需要执行存活性检测
func (s *ServiceScanStrategy) shouldPerformLivenessCheck(hosts []string) bool {
	return !Common.DisablePing && len(hosts) > 1
}

// discoverAlivePorts 发现存活的端口并触发服务探测
func (s *ServiceScanStrategy) discoverAlivePorts(hosts []string) {
	// 根据扫描模式选择端口扫描方式
	if len(hosts) > 0 {
		_ = EnhancedPortScan(hosts, Common.Ports, Common.Timeout)
	}

	// 合并额外指定的端口
	if len(Common.HostPort) > 0 {
		Common.HostPort = nil
	}
}
