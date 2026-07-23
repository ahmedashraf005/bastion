#!/bin/sh
set -eu

./efbundle --verbose
exec dotnet Bastion.Control.Api.dll
