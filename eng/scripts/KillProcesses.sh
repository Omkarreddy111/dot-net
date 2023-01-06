#!/usr/bin/env bash

# list processes that would be killed so they appear in the log
p=$(pgrep dotnet)
if [ $? -eq 0 ]
then
  echo "These processes will be killed..."
  ps -p $p
fi

pkill dotnet || true
pkill -3 crossgen2 || true
exit 0
