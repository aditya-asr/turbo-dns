#! /bin/bash

### Zone Signing Algorithm
# "FALCON512", "FALCON1024", "DILITHIUM2", "DILITHIUM5", "SPHINCS+-SHA256-128S", "RSASHA256", "ECDSA256"
export ALG="FALCON512"

export BUILDDIR="$(pwd)/build"
export WORKINGDIR="$(pwd)"
cd $WORKINGDIR

python3 build_docker_compose.py --bypass --maxudp 1232 --alg $ALG <<<"Y"

cd $BUILDDIR
docker compose down
docker compose build
cd $WORKINGDIR
./run_exps.bash 0 10 # 10 queries