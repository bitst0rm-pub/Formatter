#!/usr/bin/env perl
# -*- coding: utf-8 -*-
#
# @rev          $Format:%H$ ($Format:%h$)
# @tree         $Format:%T$ ($Format:%t$)
# @date         $Format:%ci$
# @author       $Format:%an$ <$Format:%ae$>
# @copyright    Copyright (c) 2019-present, Duc Ng. (bitst0rm)
# @link         https://github.com/bitst0rm
# @license      The MIT License (MIT)

# Disable output buffering, so print the prompt and output immediately
$| = 1;

# Print header information
print "Perl REPL - Version: $^V\n";
print "Type 'exit' to exit.\n\n";

# Check if a filename is provided as a command-line argument
if (@ARGV) {
    my $file_to_run = $ARGV[0];
    do $file_to_run;
    #exit;  # continue to run in the interactive mode
}

while (1) {
    print ">>> ";
    my $input = <STDIN>;
    last unless defined $input;  # exit the loop on Ctrl-D or Ctrl-C

    my $result = eval $input;  # evaluate the input as Perl code
    if ($@) {
        print "$@";  # print error
    } else {
        $result =~ s/\b1$//;  # remove trailing 1 caused by eval
        print "$result\n";
    }
}
