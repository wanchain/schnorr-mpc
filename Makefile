# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: schnorrmpc evm all test clean

GOBIN = build/bin
GO ?= latest

linuxDir=$(shell echo schnorrmpc-linux-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
windowsDir=$(shell echo schnorrmpc-windows-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
darwinDir=$(shell echo schnorrmpc-mac-amd64-`cat ./VERSION`-`git rev-parse --short=8 HEAD`)
# The schnorrmpc target build schnorrmpc binary

schnorrmpc:
	build/env.sh  go run   -gcflags "-N -l"    build/ci.go   install ./cmd/schnorrmpc
	build/env.sh  go run   -gcflags "-N -l"    build/ci.go   install ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/schnorrmpc\" to launch schnorrmpc."


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

schnorrmpc-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 --ldflags "-s -w"  -v ./cmd/schnorrmpc
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/schnorrmpc-linux-* | grep amd64
	mkdir -p ${linuxDir}
	cp ./build/bin/schnorrmpc-linux-* ${linuxDir}/schnorrmpc
	tar zcf ${linuxDir}.tar.gz ${linuxDir}/schnorrmpc

schnorrmpc-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 --ldflags "-s -w"  -v ./cmd/schnorrmpc
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/schnorrmpc-darwin-* | grep amd64
	mkdir -p ${darwinDir}
	cp ./build/bin/schnorrmpc-darwin-* ${darwinDir}/schnorrmpc
	tar zcf ${darwinDir}.tar.gz ${darwinDir}/schnorrmpc


schnorrmpc-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 --ldflags "-s -w"  -v ./cmd/schnorrmpc
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/schnorrmpc-windows-* | grep amd64
	mkdir -p ${windowsDir}
	cp ./build/bin/schnorrmpc-windows-* ${windowsDir}/schnorrmpc.exe
	zip ${windowsDir}.zip ${windowsDir}/schnorrmpc.exe

release: clean schnorrmpc-linux-amd64 schnorrmpc-windows-amd64 schnorrmpc-darwin-amd64


