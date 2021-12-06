package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/poolpOrg/go-dht"
)

type Agent struct {
	id         [32]byte
	dht        *dht.DHT
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	address    string
}

func NewAgent(addr string) (*Agent, error) {
	pubkeyCurve := elliptic.P384()

	privateKey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	x509pub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	dht, err := dht.NewDHT(x509pub, addr)
	if err != nil {
		return nil, err
	}

	return &Agent{
		id:         sha256.Sum256(x509pub),
		dht:        dht,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		address:    addr,
	}, nil
}

func (agent *Agent) Join(join_addr string) {
	node := agent.dht.Self()
	node.Join(join_addr)
	<-make(chan bool)
}

func (agent *Agent) Run() {
	<-make(chan bool)
}

func main() {
	var node_addr string
	var join_addr string
	flag.StringVar(&node_addr, "address", "127.0.0.1:9876", "node address")
	flag.StringVar(&join_addr, "join", "", "join node address")
	flag.Parse()

	agent, _ := NewAgent(node_addr)
	fmt.Printf("%02x: started\n", agent.id)

	if join_addr != "" {
		agent.Join(join_addr)
	}

	agent.Run()
}
