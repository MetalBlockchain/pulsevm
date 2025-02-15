package engine

import "github.com/MetalBlockchain/pulsevm/chain/name"

type ResourceTracker struct {
	netUsage map[name.Name]int
	ramUsage map[name.Name]int
	cpuUsage map[name.Name]int
}

func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{
		netUsage: make(map[name.Name]int),
		ramUsage: make(map[name.Name]int),
		cpuUsage: make(map[name.Name]int),
	}
}

func (rt *ResourceTracker) AddNetUsage(account name.Name, delta int) {
	rt.netUsage[account] += delta
}

func (rt *ResourceTracker) AddRamUsage(account name.Name, delta int) {
	rt.ramUsage[account] += delta
}

func (rt *ResourceTracker) AddCpuUsage(account name.Name, delta int) {
	rt.cpuUsage[account] += delta
}
