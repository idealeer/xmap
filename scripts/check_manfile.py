#!/usr/bin/env python
#
# CI runs this script to verify that options appearing in XTools' ggo.in files also appear in their .ronn files.
# It does not check that `make manpages` has actually been run.
#
# This script assumes it's being run from the root of the xmap repository.
#

import sys

checks = [
    ("xopt.ggo.in", "xmap.1.ronn")
]

failures = False

for ggo, ronn in checks:
    options = []
    with open("src/" + ggo) as fd:
        for l in fd:
            if l.startswith("option "):
                option = l.split()[1].lstrip('"').rstrip('"')
                options.append(option)

    man = open("src/" + ronn).read()

    for option in options:
        if option not in man:
            failures = True
            sys.stderr.write("option %s is present in %s but missing from man file %s\n" % (option, ggo, ronn))

if failures:
    sys.exit(1)
