#!/usr/bin/perl -w

use strict;

use Test::Harness;

$Test::Harness::verbose = 1
	if $ARGV[0] && $ARGV[0] eq '-v';

runtests('NodeTest.t');

