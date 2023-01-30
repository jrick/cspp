package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"log"
	"sort"

	"github.com/decred/dcrd/crypto/blake256"
)

var (
	flagNodes       = flag.Int("nodes", 32, "number of simulator nodes")
	flagPeers       = flag.Int("peers", 8, "number of mixing peers")
	flagNodeConns   = flag.Int("nodeconns", 8, "total (outbound+inbound) internode connections")
	flagPeerConns   = flag.Int("peerconns", 8, "outbound peer connections to nodes")
	flagDelayedRate = flag.Int("delayedrate", 0, "percentage (0-100) of time messages fail to send in time")
)

// the simulator demonstrates the pair grouping done in two messaging rounds, not a full mix,
// but the same concepts will apply.
// visible will be empty in the first message, but contains all seen peer messages in the second.
// in the actual mix, visible should be the verified signatures (or a message hash that commits
// to them), and from it, a session id can be derived.
type message struct {
	pubkey    []byte
	visible   [][]byte
	signature []byte
}

type node struct {
	id       int
	messages map[*message]struct{}
	conns    map[int]*node
	peers    map[int]*peer
}

type peer struct {
	id       int
	pubkey   []byte
	messages map[*message]struct{}
	delayed  map[*message]struct{}
	nodes    map[int]*node
}

func main() {
	flag.Parse()

	nodes := make([]*node, *flagNodes)
	peers := make([]*peer, *flagPeers)

	for i := 0; i < *flagNodes; i++ {
		n := &node{
			id:       i,
			messages: make(map[*message]struct{}),
			conns:    make(map[int]*node),
			peers:    make(map[int]*peer),
		}
		nodes[n.id] = n
	}
	for _, n := range nodes {
		for len(n.conns) < *flagNodeConns {
			n2 := randSliceElem(nodes)
			if n.id == n2.id {
				continue
			}
			if _, ok := n.conns[n2.id]; ok {
				continue
			}
			log.Printf("connecting node-%v to node-%v", n.id, n2.id)
			n.conns[n2.id] = n2
			n2.conns[n.id] = n
		}
	}
	for i := 0; i < *flagPeers; i++ {
		pubkey := make([]byte, 32)
		rand.Read(pubkey)
		p := &peer{
			id:       i,
			pubkey:   pubkey,
			messages: make(map[*message]struct{}),
			nodes:    make(map[int]*node),
		}
		peers[p.id] = p
	}
	for _, p := range peers {
		for len(p.nodes) < *flagPeerConns {
			n := randSliceElem(nodes)
			if _, ok := p.nodes[n.id]; ok {
				continue
			}
			log.Printf("connecting peer-%v to node-%v", p.id, n.id)
			p.nodes[n.id] = n
			n.peers[p.id] = p
		}
	}

	for i := 0; i < len(peers); i++ {
		peers[i].publish()
	}
	for i := 0; i < len(peers); i++ {
		peers[i].publish()
	}

	// check for pairings (must have matching session ids).
	//
	// even at higher error rates (eg 50%), with the rest of the default
	// flags, this seems to work well nearly all of the time.
	for i := 0; i < len(peers); i++ {
		p := peers[i]
		var visible [][]byte
		for m := range p.messages {
			visible = append(visible, m.pubkey)
		}
		sort.Slice(visible, func(i, j int) bool {
			return bytes.Compare(visible[i], visible[j]) == -1
		})
		h := blake256.New()
		for _, sig := range visible {
			h.Write(sig)
		}
		sid := h.Sum(nil)
		log.Printf("peer-%v: %v peers in sid=%x\n", p.id, len(visible), sid)
	}
}

func (p *peer) publish() {
	var visible [][]byte
	visibleMap := make(map[string]struct{})
	for m := range p.messages {
		if _, ok := visibleMap[string(m.pubkey)]; ok {
			continue
		}
		visible = append(visible, m.pubkey)
		visibleMap[string(m.pubkey)] = struct{}{}
	}
	sort.Slice(visible, func(i, j int) bool {
		return bytes.Compare(visible[i], visible[j]) == -1
	})
	m := &message{
		pubkey:  p.pubkey,
		visible: visible,
	}
	// we know our own sent messages. the rest are "inv'd".
	p.messages[m] = struct{}{}
	for _, n := range p.nodes {
		n.inv(p, m)
	}
}

func (n *node) inv(from *peer, m *message) {
	// force scenerio where none of the other peers sees peer 0.
	//if from != nil && from.id == 0 {
	//	return
	//}
	if _, ok := n.messages[m]; ok {
		return
	}
	if randUint32n(100) < uint32(*flagDelayedRate) {
		return
	}
	n.messages[m] = struct{}{}
	for _, p := range n.peers {
		if p == from {
			continue
		}
		p.messages[m] = struct{}{}
	}
	for _, n2 := range n.conns {
		n2.inv(nil, m)
	}
}
