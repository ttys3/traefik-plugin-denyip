#!/usr/bin/env bash

set -eou pipefail

traefik --configFile=./traefik.yaml

