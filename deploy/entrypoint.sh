#!/bin/sh
set -e

# Migrations are the binary's job: it reads RUN_MIGRATION (default true) itself.
exec ./main "$@"
