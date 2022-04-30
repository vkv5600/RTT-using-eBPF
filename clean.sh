#!/bin/bash

sudo tc filter del dev $1 ingress prio 1 handle 3 bpf
sudo tc filter del dev $1 egress prio 1 handle 3 bpf
sudo tc qdisc del dev $1 clsact
