package engine

import "github.com/MetalBlockchain/pulsevm/chain/name"

type ResourceTracker struct {
	netUsage map[name.Name]uint64
	ramUsage map[name.Name]uint64
	cpuUsage map[name.Name]uint64
}

func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{
		netUsage: make(map[name.Name]uint64),
		ramUsage: make(map[name.Name]uint64),
		cpuUsage: make(map[name.Name]uint64),
	}
}

func (rt *ResourceTracker) AddNetUsage(account name.Name, delta uint64) {
	rt.netUsage[account] += delta
}

func (rt *ResourceTracker) AddRamUsage(account name.Name, delta uint64) {
	rt.ramUsage[account] += delta
}

func (rt *ResourceTracker) AddCpuUsage(account name.Name, delta uint64) {
	rt.cpuUsage[account] += delta
}
