#!/bin/sh
# hello-x86_64 is pre-staged; build.sh just copies the staged tree into
# DESTDIR. A real recipe would compile and install instead.
set -eu
cp -a "$SOURCE_DIR/." "$DESTDIR/"
