.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/wanchain/schnorr-mpc/cmd/swarm
	go build -o bin/geth     github.com/wanchain/schnorr-mpc/cmd/geth
	go build -o bin/bootnode github.com/wanchain/schnorr-mpc/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/wanchain/schnorr-mpc/swarm/...
