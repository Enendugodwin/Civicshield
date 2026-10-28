#!/bin/sh
# Seed the SQLite demo database.
cd "$(dirname "$0")/../backend" || exit 1
python -m app.seed
