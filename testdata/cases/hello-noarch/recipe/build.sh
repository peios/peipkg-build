#!/bin/sh
# hello-noarch is pre-staged; build.sh is a noop.
# In a real recipe this would compile + install into $DESTDIR.
set -eu
cp -a "$SOURCE_DIR/." "$DESTDIR/"
