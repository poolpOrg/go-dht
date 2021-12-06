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
	"crypto/sha256"
	"math/big"
	"sort"
	"sync"
	"time"
)

const (
	k = sha256.Size
	m = k << 3
)

type DHT struct {
	PublicKey []byte
	Address   string

	finger [m][][32]byte

	muNodes sync.Mutex
	nodes   map[[k]byte]*Node
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
		dht.finger[i] = make([][32]byte, 0)
	}
	dht.nodes = make(map[[k]byte]*Node)
	dht.AddNode(NewNode(dht, publicKey, nodeAddress))
	return dht, nil
}

func (_dht *DHT) Self() *Node {
	return _dht.nodes[sha256.Sum256(_dht.PublicKey)]
}

func (_dht *DHT) AddNode(node *Node) {
	_dht.muNodes.Lock()
	_dht.nodes[node.Id] = node
	_dht.muNodes.Unlock()
	_dht.updateFingerTable()
	node.run()
}

func (_dht *DHT) RemoveNode(node *Node) {
	_dht.muNodes.Lock()
	defer _dht.muNodes.Unlock()
	delete(_dht.nodes, node.Id)
	_dht.updateFingerTable()
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

func (_dht *DHT) updateFingerTable() {
	var finger [m][][32]byte
	for i := 0; i < m; i++ {
		finger[i] = make([][32]byte, 0)
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
		finger[vnodeID[0]] = append(finger[vnodeID[0]], vnodeID)
	}
	_dht.finger = finger
}

func NewNode(dht *DHT, publicKey []byte, address string) *Node {
	nodeID := sha256.Sum256(publicKey)
	node := &Node{
		dht:       dht,
		Id:        nodeID,
		Address:   address,
		PublicKey: publicKey,
	}
	for i := 0; i < len(node.VNodes); i++ {
		node.VNodes[i] = compute_vnode_offset(node.Id, int64(i), m)
	}
	return node
}

func (node *Node) run() {
	if bytes.Compare(node.PublicKey[:], node.dht.PublicKey[:]) == 0 {
		go node.dht.Listen(node.Address)
	} else {
		go func() {
			for {
				t, success := node.ping()
				if !success {
					// XXX - disable but don't evict nodes until they failed for > limit ?
					node.dht.RemoveNode(node)
					break
				}

				// XXX - evict nodes with a high latency > ?
				node.latency = t
				time.Sleep(time.Second * 1)
			}
		}()
	}
}

func (node *Node) ping() (time.Duration, bool) {
	return networkPing(node)
}

func (_dht *DHT) Joined(peer *Node) {
	if _, exists := _dht.nodes[peer.Id]; !exists {
		_dht.AddNode(peer)

		for nodeID, next := range _dht.nodes {
			if nodeID != peer.Id {
				go next.Join(peer.Address)
			}
		}
	}
}

func (node *Node) Join(peer_addr string) {
	peer := networkJoin(node, peer_addr)
	if !bytes.Equal(node.PublicKey[:], node.dht.PublicKey[:]) {
		return
	}
	go node.dht.Joined(peer)
}

func (node *Node) Lookup(key [32]byte) [32]byte {
	i := int(key[0])
	for {
		for _, vnodeID := range node.dht.finger[i] {
			if bytes.Compare(key[:], vnodeID[:]) < 0 || vnodeID[0] < key[0] {
				return vnodeID
			}
		}
		i = (i + 1) % len(node.dht.finger)
	}
}

func compute_vnode_offset(n [32]byte, i int64, m int64) [32]byte {
	big_two, big_i, big_m := big.NewInt(2), big.NewInt(i), big.NewInt(m)
	two_pow_m := big.NewInt(0).Exp(big_two, big_m, nil)

	slice := &big.Int{}
	slice.Div(two_pow_m, big.NewInt(int64(len(n))))

	n_slice := &big.Int{}
	n_slice.Set(big_i).Mul(n_slice, slice).Mod(n_slice, two_pow_m)

	res := &big.Int{}
	res.SetBytes(n[:]).Add(res, n_slice).Mod(res, two_pow_m)

	var ret [32]byte
	copy(ret[:], res.Bytes())

	return ret
}
