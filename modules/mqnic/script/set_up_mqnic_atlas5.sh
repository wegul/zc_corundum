#!/bin/bash

DIR="/home/weigao/zc_corundum/modules/mqnic"
MK_FLAG=1

echo "sudo rmmod mqnic"
sudo rmmod mqnic

# echo "Clean module: make clean"
# make clean

for file in "${DIR}"/*; do
    if [[ "${file}" =~ ^.*"mqnic.ko" ]]; then
        echo "Module exists: ${file}"
        MK_FLAG=0
    fi
done

if [[ MK_FLAG -eq 1 ]]; then
    echo "No module, execute Makefile: make"
    make DEBUG=1 -j32
    set -e
fi


echo "sudo insmod ${DIR}/mqnic.ko"
sudo insmod ${DIR}/mqnic.ko


echo "sudo ip link set dev enp175s0np0 up"
sudo ip link set dev enp175s0np0 up

echo "sudo ip addr add 10.0.0.5/24 dev enp175s0np0"
sudo ip addr add 10.0.0.5/24 dev enp175s0np0

echo "sudo ip link set dev enp175s0np1 up"
sudo ip link set dev enp175s0np1 up

echo "sudo ip addr add 10.0.1.5/24 dev enp175s0np1"
sudo ip addr add 10.0.1.5/24 dev enp175s0np1

echo "sudo arp -s 10.0.0.4 00:0a:35:06:1a:08"
sudo arp -s 10.0.0.4 00:0a:35:06:1a:08

echo "sudo arp -s 10.0.1.4 00:0a:35:06:1a:09"
sudo arp -s 10.0.1.4 00:0a:35:06:1a:09
# sleep 1
# sudo dmesg -l debug,err,emerg,crit | tail -2000 > ./crash.log