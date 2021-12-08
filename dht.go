/*
 * Copyright (c) 2021 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * HE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package dht

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"sort"
	"sync"
	"time"
)

const (
	k = sha256.Size
	m = k << 3
	r = 3 // replicas, bump
)

type DHT struct {
	PublicKey []byte
	Address   string

	muRouting sync.Mutex
	routing   [m][][32]byte

	muNodes sync.Mutex
	nodes   map[[k]byte]*Node

	muData sync.Mutex
	data   map[[k]byte][]byte
}

type Node struct {
	dht       *DHT
	Id        [k]byte
	VNodes    [k][k]byte
	Address   string
	PublicKey []byte
	latency   time.Duration
}

func NewDHT(publicKey []byte, nodeAddress string) (*DHT, error) {
	dht := &DHT{}
	dht.PublicKey = publicKey
	dht.Address = nodeAddress
	for i := 0; i < m; i++ {
		dht.routing[i] = make([][32]byte, 0)
	}
	dht.nodes = make(map[[k]byte]*Node)
	dht.data = make(map[[k]byte][]byte)
	dht.AddNode(NewNode(dht, publicKey, nodeAddress))

	go dht.Listen(nodeAddress)
	go dht.checkNodes()

	return dht, nil
}

func (_dht *DHT) Self() *Node {
	return _dht.nodes[sha256.Sum256(_dht.PublicKey)]
}

func (_dht *DHT) AddNode(node *Node) {
	_dht.muNodes.Lock()
	_dht.nodes[node.Id] = node
	_dht.muNodes.Unlock()
	_dht.updateRoutingTable()
}

func (_dht *DHT) RemoveNode(node *Node) {
	_dht.muNodes.Lock()
	defer _dht.muNodes.Unlock()
	delete(_dht.nodes, node.Id)
	_dht.updateRoutingTable()
}

func (_dht *DHT) Lookup(key [32]byte) [32]byte {
	_dht.muRouting.Lock()
	defer _dht.muRouting.Unlock()
	i := int(key[0])
	for {
		for _, vnodeID := range _dht.routing[i] {
			if bytes.Compare(key[:], vnodeID[:]) < 0 || vnodeID[0] < key[0] {
				return vnodeID
			}
		}
		i = (i + 1) % len(_dht.routing)
	}
}

func (_dht *DHT) VNodeLookup(id [32]byte) *Node {
	_dht.muNodes.Lock()
	defer _dht.muNodes.Unlock()
	for _, node := range _dht.nodes {
		for _, vnodeID := range node.VNodes {
			if vnodeID == id {
				return node
			}
		}
	}
	return nil
}

func (_dht *DHT) VNodeNext(id [32]byte) [32]byte {
	_dht.muNodes.Lock()
	defer _dht.muNodes.Unlock()
	i := int(id[0])
	isNext := false
	for {
		for _, vnodeID := range _dht.routing[i] {
			if isNext {
				return vnodeID
			}
			if bytes.Equal(id[:], vnodeID[:]) {
				isNext = true
			}
		}
		i = (i + 1) % len(_dht.routing)
	}
}

func (_dht *DHT) checkNodes() {
	for {
		var wg sync.WaitGroup
		for _, node := range _dht.nodes {
			if node == _dht.Self() {
				continue
			}
			wg.Add(1)
			go func(node *Node) {
				for {
					buffer := make([]byte, 4096)
					_, err := rand.Read(buffer)
					if err != nil {
					} else {
						t, success := networkLookup(node, sha256.Sum256(buffer))
						if !success {
							// XXX - disable but don't evict nodes until they failed for > limit ?
							node.dht.RemoveNode(node)
							break
						}
						// XXX - evict nodes with a high latency > ?
						node.latency = t
					}
					nBig, err := rand.Int(rand.Reader, big.NewInt(10))
					if err != nil {
						panic(err)
					}
					n := nBig.Int64()
					time.Sleep(time.Second * time.Duration(n))
				}
				wg.Done()
			}(node)
		}
		wg.Wait()
	}
}

func (_dht *DHT) updateRoutingTable() {
	var routing [m][][32]byte
	for i := 0; i < m; i++ {
		routing[i] = make([][32]byte, 0)
	}

	ring := make([][32]byte, 0)
	for _, n := range _dht.nodes {
		for _, vnode := range n.VNodes {
			ring = append(ring, vnode)
		}
	}
	sort.Slice(ring, func(i, j int) bool {
		return bytes.Compare(ring[i][:], ring[j][:]) < 0
	})

	for _, vnodeID := range ring {
		routing[vnodeID[0]] = append(routing[vnodeID[0]], vnodeID)
	}
	_dht.routing = routing
}

func (_dht *DHT) Put(key [32]byte, value []byte) {
	_dht.muData.Lock()
	defer _dht.muData.Unlock()
	_dht.data[key] = value
}

func (_dht *DHT) Get(key [32]byte) ([]byte, bool) {
	_dht.muData.Lock()
	defer _dht.muData.Unlock()
	value, exists := _dht.data[key]
	return value, exists
}

func NewNode(dht *DHT, publicKey []byte, address string) *Node {
	nodeID := sha256.Sum256(publicKey)
	node := &Node{
		dht:       dht,
		Id:        nodeID,
		Address:   address,
		PublicKey: publicKey,
	}
	node.VNodes[0] = nodeID
	for i := 1; i < len(node.VNodes); i++ {
		node.VNodes[i] = sha256.Sum256(node.VNodes[i-1][:])
	}
	return node
}

func (_dht *DHT) Joined(peer *Node) {
	if _, exists := _dht.nodes[peer.Id]; !exists {
		_dht.AddNode(peer)
		for nodeID, next := range _dht.nodes {
			if nodeID != peer.Id {
				next.Join(peer.Address)
			}
		}
	}
}

func (node *Node) Join(peer_addr string) {
	peer := networkJoin(node, peer_addr)
	if !bytes.Equal(node.PublicKey[:], node.dht.PublicKey[:]) {
		return
	}
	node.dht.Joined(peer)
}

func (node *Node) Put(key []byte, value []byte) {
	keysum := sha256.Sum256(key)
	vnodeID := node.dht.Lookup(keysum)
	dest := node.dht.VNodeLookup(vnodeID)

	if dest == node {
		node.dht.Put(keysum, value)
	} else {
		// on non-responsible node, store if replica or forward to responsible
		isReplica := false
		if isReplica {
			node.dht.Put(keysum, value)
		} else {
			networkPut(dest, key, value)
		}
	}
}

func (node *Node) Get(key []byte) ([]byte, bool) {
	keysum := sha256.Sum256(key)
	vnodeID := node.dht.Lookup(keysum)
	dest := node.dht.VNodeLookup(vnodeID)
	if dest == node {
		return node.dht.Get(keysum)
	} else {
		return networkGet(dest, key)
	}
}
