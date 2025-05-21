# Lab3 RCA

Welcome to Lab 3 - RCA (Root-Cause Analysis)!

First, run `setup.sh`. It will generate the port number and
group secret for tinyserv to work. You only need to run it once.

After that, you'll want to build and run the tinyserv that lives in
the target directory, and try running the sploits against it!

Feel free to make any modifications you want to the target to help you
perform the root cause analysis, or to test a patch idea.

`handin.sh` will generate a diff (patch file showing what lines were
added and removed) for the current `target/tinyserv/main.c` (or one
your specify.)

## target
Contains the application being attacked (tinyserv)

For the purposes of the lab, pretend that only the `target/` directory
is the open-source project you are maintaining (if someone were to git
clone tinyserv, they would get everything in there.) All the rest of
the things here are just to make the lab work.

## sploits
Contains the exploits you have received that work on tinyserv.

## turnins
This will hold your most recent patches, as well as timestamped
backups of your `main.c` for each time you ran `handin.sh`.
