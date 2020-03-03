#!/bin/bash

# Install project-specific system dependencies
apt-get install -y --no-install-recommends \
  libpq-dev \
  # The final line has been added to keep the diffs "clean" as additions can be
  # made in a manner that flag the lines with the newly added, removed or
  # modified packages without forcing the user to consider punctuation for line
  # continuation for example. This becomes annoying for the last line where one
  && return 0

# https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_02_01
