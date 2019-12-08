#!/usr/bin/env bash
cat /run/smith_hids.pid |xargs kill -9
rmmod smith.ko