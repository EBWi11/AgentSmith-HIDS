#!/usr/bin/env bash
cat /run/smith.pid |xargs kill -9
rmmod syshook.ko