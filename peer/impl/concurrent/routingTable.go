package concurrent

import (
	"go.dedis.ch/cs438/peer"
	"sync"
)

func NewRoutingTable() RoutingTable {
	routingTable := make(peer.RoutingTable)
	safeTable := &SafeTable{
		routingTable: routingTable,
	}
	return RoutingTable{safeTable}
}

type RoutingTable struct {
	table *SafeTable
}

func (m *SafeTable) set(key, val string) {
	m.Lock()
	defer m.Unlock()
	if val != "" {
		m.routingTable[key] = val
	} else {
		delete(m.routingTable, key)
	}
}

func (m *SafeTable) get(key string) (string, bool) {
	m.Lock()
	defer m.Unlock()
	elem, ok := m.routingTable[key]
	return elem, ok
}

type SafeTable struct {
	sync.Mutex
	routingTable peer.RoutingTable
}

func (crt *RoutingTable) AddEntry(key, val string) {
	crt.table.set(key, val)
}

func (crt *RoutingTable) GetEntry(key string) (string, bool) {
	return crt.table.get(key)
}

func (crt *RoutingTable) GetEntries() peer.RoutingTable {
	return crt.table.routingTable
}

func (crt *RoutingTable) Copy() map[string]string {
	copyTable := make(map[string]string)
	crt.table.Lock()
	for key, value := range crt.GetEntries() {
		copyTable[key] = value
	}
	crt.table.Unlock()
	return copyTable
}
