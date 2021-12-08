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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type reqJoin struct {
	PublicKey string
	Address   string
}

type nodeInfo struct {
	PublicKey string
	Address   string
}

func networkLookup(peer *Node, key [32]byte) (time.Duration, bool) {
	url := fmt.Sprintf("http://%s/lookup/"+fmt.Sprintf("%02x", key), peer.Address)

	t0 := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return time.Since(t0), true
}

func networkJoin(node *Node, peer_addr string) *Node {
	reqJoin := reqJoin{
		PublicKey: base64.RawURLEncoding.EncodeToString(node.PublicKey),
		Address:   node.Address,
	}
	postBody, _ := json.Marshal(reqJoin)

	url := fmt.Sprintf("http://%s/join", peer_addr)

	//resp, err := http.Get("http://%sjsonplaceholder.typicode.com/posts/1")
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	var res nodeInfo
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&res); err != nil {
		log.Fatalln(err)
	}

	peer_publicKey, err := base64.RawURLEncoding.DecodeString(resp.Header.Get("Public-Key"))
	if err != nil {
		log.Fatalln(err)
	}
	return NewNode(node.dht, peer_publicKey, peer_addr)
}

func networkPing(peer *Node) (time.Duration, bool) {
	req := nodeInfo{}
	req.PublicKey = base64.RawURLEncoding.EncodeToString(peer.dht.PublicKey)
	req.Address = peer.dht.Address
	postBody, _ := json.Marshal(req)

	url := fmt.Sprintf("http://%s/ping", peer.Address)

	t0 := time.Now()
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return time.Since(t0), true
}

func networkPut(peer *Node, key []byte, value []byte) bool {
	url := fmt.Sprintf("http://%s/store/%s", peer.Address, string(key))
	resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(value))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

func networkGet(peer *Node, key []byte) ([]byte, bool) {
	url := fmt.Sprintf("http://%s/store/%s", peer.Address, string(key))
	resp, err := http.Get(url)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	return b, true
}

func (_dht *DHT) Listen(address string) {
	r := mux.NewRouter()
	r.HandleFunc("/debug", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(w, "<pre>\n")

		fmt.Fprintf(w, "PublicKey: %s\n", base64.RawStdEncoding.EncodeToString(_dht.PublicKey))
		fmt.Fprintf(w, "Node: %02x\n", sha256.Sum256(_dht.PublicKey))

		fmt.Fprintf(w, "\nknown nodes on the ring:\n")
		for _, v := range _dht.nodes {
			fmt.Fprintf(w, "\t%02x %s %s\n", v.Id, v.Address, v.latency)
		}

		fmt.Fprintf(w, "\nkeys on node (%d):\n", len(_dht.data))
		for k, _ := range _dht.data {
			fmt.Fprintf(w, "\t%02x\n", k)
		}

		fmt.Fprintf(w, "<pre>\n")
	})

	r.HandleFunc("/join", func(w http.ResponseWriter, req *http.Request) {
		var reqJoin reqJoin
		decoder := json.NewDecoder(req.Body)
		if err := decoder.Decode(&reqJoin); err != nil {
			log.Fatalln(err)
		}

		peerPublicKey, err := base64.RawURLEncoding.DecodeString(reqJoin.PublicKey)
		if err != nil {
			log.Fatalln(err)
		}
		_ = peerPublicKey
		node := NewNode(_dht, peerPublicKey, reqJoin.Address)
		_dht.Joined(node)

		var resJoin nodeInfo
		resJoin.PublicKey = base64.RawURLEncoding.EncodeToString(_dht.PublicKey)
		resJoin.Address = _dht.Address

		w.Header().Add("Public-Key", base64.RawURLEncoding.EncodeToString(_dht.PublicKey))

		json.NewEncoder(w).Encode(&resJoin)

	})

	r.HandleFunc("/ping", func(w http.ResponseWriter, req *http.Request) {
		var reqNode nodeInfo
		decoder := json.NewDecoder(req.Body)
		if err := decoder.Decode(&reqNode); err != nil {
			log.Fatalln(err)
		}
		w.Header().Add("Public-Key", base64.RawURLEncoding.EncodeToString(_dht.PublicKey))
	})

	r.HandleFunc("/lookup/{key}", func(w http.ResponseWriter, req *http.Request) {

		vars := mux.Vars(req)
		key := vars["key"]
		fmt.Println("server: received LOOKUP", key)

		keysum := sha256.Sum256([]byte(key))
		vnodeID := _dht.Lookup(keysum)
		node := _dht.VNodeLookup(vnodeID)

		var res nodeInfo
		res.PublicKey = base64.RawURLEncoding.EncodeToString(node.PublicKey)
		res.Address = node.Address

		w.Header().Add("Public-Key", base64.RawURLEncoding.EncodeToString(_dht.Self().PublicKey))

		json.NewEncoder(w).Encode(&res)
	})

	r.HandleFunc("/store/{key}", func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		key := vars["key"]

		b, _ := io.ReadAll(req.Body)
		_dht.Self().Put([]byte(key), b)

		w.Header().Add("Public-Key", base64.RawURLEncoding.EncodeToString(_dht.Self().PublicKey))
	}).Methods("POST")

	r.HandleFunc("/store/{key}", func(w http.ResponseWriter, req *http.Request) {
		fmt.Println("server: received GET")

		vars := mux.Vars(req)
		key := vars["key"]

		data, exists := _dht.Self().Get([]byte(key))
		if !exists {
			w.WriteHeader(404)
			return
		}
		w.Write(data)

		w.Header().Add("Public-Key", base64.RawURLEncoding.EncodeToString(_dht.Self().PublicKey))
	}).Methods("GET")

	http.ListenAndServe(address, r)
}
