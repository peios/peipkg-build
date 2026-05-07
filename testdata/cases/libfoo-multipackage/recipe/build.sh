#!/bin/sh
# libfoo-multipackage is pre-staged; build.sh just copies the staged tree
# into DESTDIR. A real recipe would run upstream's build system instead.
set -eu
cp -a "$SOURCE_DIR/." "$DESTDIR/"
