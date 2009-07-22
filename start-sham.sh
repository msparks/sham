#!/bin/sh
PHRASE="I would much rather hear more about your whittling project"

cd `dirname $0`
nice ./sham $1 "$PHRASE" < wordlist
