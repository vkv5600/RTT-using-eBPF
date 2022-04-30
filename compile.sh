#!/bin/bash

sudo tc qdisc add dev $1 clsact
clang -O2 -g -S -emit-llvm -DDEBUG -c $2 -o - | llc -march=bpf -filetype=obj -o out.o

sudo tc filter add dev $1 ingress prio 1 handle 3 bpf da obj out.o section flow1 verbose

sudo tc filter add dev $1 egress prio 1 handle 3 bpf da obj out.o section flow2 verbose

sudo cat /sys/kernel/tracing/trace_pipe


