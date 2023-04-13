#!/bin/sh

count=1
while true; do
    printf "[%4d] $HELLO\n" $count
    count=$((count+1))
    sleep 5
done