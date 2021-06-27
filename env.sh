#! /bin/bash

for line in $(cat .env)
do
    $(heroku config:set $line)
done
