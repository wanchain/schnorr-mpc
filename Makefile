# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: mpc evm all test clean

GOBIN = build/bin
GO ?= latest

linuxDir=$(shell echo mpc-linux-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
windowsDir=$(shell echo mpc-windows-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
darwinDir=$(shell echo mpc-mac-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
# The mpc target build mpc binary

mpc:
	build/env.sh  go run   -gcflags "-N -l"    build/ci.go   install ./cmd/mpc
	build/env.sh  go run   -gcflags "-N -l"    build/ci.go   install ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/mpc\" to launch mpc."


# The clean target clear all the build output
clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/jteeuwen/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go install ./cmd/abigen



# Cross Compilation Targets (xgo)

mpc-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 --ldflags "-s -w"  -v ./cmd/mpc
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/mpc-linux-* | grep amd64
	mkdir -p ${linuxDir}
	cp ./build/bin/mpc-linux-* ${linuxDir}/mpc
	tar zcf ${linuxDir}.tar.gz ${linuxDir}/mpc

mpc-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 --ldflags "-s -w"  -v ./cmd/mpc
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/mpc-darwin-* | grep amd64
	mkdir -p ${darwinDir}
	cp ./build/bin/mpc-darwin-* ${darwinDir}/mpc
	tar zcf ${darwinDir}.tar.gz ${darwinDir}/mpc


mpc-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 --ldflags "-s -w"  -v ./cmd/mpc
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/mpc-windows-* | grep amd64
	mkdir -p ${windowsDir}
	cp ./build/bin/mpc-windows-* ${windowsDir}/mpc.exe
	zip ${windowsDir}.zip ${windowsDir}/mpc.exe

release: clean mpc-linux-amd64 mpc-windows-amd64 mpc-darwin-amd64


