#!/bin/bash

set -euo pipefail
clear

TARGET=x86_64-w64-mingw32

make TARGET=$TARGET LKL=1 LKL_DIR=../../../../linux WINDOWS=1 -B
