# tinyserv

A very cool open-source single-threaded HTTP server.

# Building

run `make` in the tinyserv directory

# Usage

run `./tinyserv ./files` or `./tinyserv ./files &` from the
`tinyserv/` directory. The command with the `&` will
background the process so you can reuse the same terminal to run other
commands; if you use the `&`, then make sure you kill the process
after you are done.

You can then talk to it via your favorite web browser, e.g. if you are
running on umnak and your port number is 4938:
http://umnak.cs.washington.edu:4938/

Make sure to use the hostname you are running on, and your port
number!
