#!/bin/sh
 
set -e
                                                  
if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
ethdir="$workspace/src/github.com/wanchain"
if [ ! -L "$ethdir/schnorr-mpc" ]; then
    mkdir -p "$ethdir"
    cd "$ethdir"
    ln -s ../../../../../. schnorr-mpc
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$ethdir/schnorr-mpc"
PWD="$ethdir/schnorr-mpc"

# Launch the arguments with the configured environment.
exec "$@"
