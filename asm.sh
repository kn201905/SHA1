#!/bin/sh
rm SHA1.o
nasm -f elf64 -o SHA1.o SHA1.asm

