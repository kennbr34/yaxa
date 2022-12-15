#!/bin/bash

echo "./cli -e -i ./cli.c -o ./cli.c.enc -p password"
./cli -e -i ./cli.c -o ./cli.c.enc -p password
echo "./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password"
./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password
echo "cmp ./cli.c ./cli.c.plain"
cmp ./cli.c ./cli.c.plain

echo "./cli -e -i ./cli.c -o ./cli.c.enc -k ./README.md"
./cli -e -i ./cli.c -o ./cli.c.enc -k ./README.md
echo "./cli -d -i ./cli.c.enc -o ./cli.c.plain -k ./README.md"
./cli -d -i ./cli.c.enc -o ./cli.c.plain -k ./README.md
echo "cmp ./cli.c ./cli.c.plain"
cmp ./cli.c ./cli.c.plain

echo "./cli -e -i ./cli.c -o ./cli.c.enc -O /dev/urandom"
./cli -e -i ./cli.c -o ./cli.c.enc -O /dev/urandom
echo "./cli -d -i ./cli.c.enc -o ./cli.c.plain -O ./cli.c.enc.pad"
./cli -d -i ./cli.c.enc -o ./cli.c.plain -O ./cli.c.enc.pad
echo "cmp ./cli.c ./cli.c.plain"
cmp ./cli.c ./cli.c.plain

echo "./cli -e -i ./cli.c -o ./cli.c.enc -p password -k ./README.md"
./cli -e -i ./cli.c -o ./cli.c.enc -p password -k ./README.md
echo "./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password -k ./README.md"
./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password -k ./README.md
echo "cmp ./cli.c ./cli.c.plain"
cmp ./cli.c ./cli.c.plain

echo "./cli -e -i ./cli.c -o ./cli.c.enc -p password -O /dev/urandom"
./cli -e -i ./cli.c -o ./cli.c.enc -p password -O /dev/urandom
echo "./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password -O ./cli.c.enc.pad"
./cli -d -i ./cli.c.enc -o ./cli.c.plain -p password -O ./cli.c.enc.pad
echo "cmp ./cli.c ./cli.c.plain"
cmp ./cli.c ./cli.c.plain


