#!/bin/bash

# cd  ../schnorr-mpc-bak
# files=`git diff --name-only`


# for f in ${files[@]}; do
#        cp ${f} ../schnorr-mpc/${f}
# done

cd ../schnorr-mpc
make
cp ./build/bin/gwan ../pos6/bin/
cd ../pos6
docker build . -t wanchain/client-go:2.0.0-beta.5
docker push wanchain/client-go:2.0.0-beta.5