#!/usr/bin/env bash

# replace this with your own associated public key
PK=EOS5qcuysV9KcJjG2toE34Zq9wS5jLNgqhWgvzntt9C7Ce6dbjTSR

cleos wallet unlock
cleos create account eosio test $PK -p eosio@active
cleos create account eosio sch.verify $PK -p eosio@active