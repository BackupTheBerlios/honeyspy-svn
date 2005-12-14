#!/usr/bin/perl -w

use strict;

use Test::Simple tests => 7;
use lib '..';
use Commons;

my %DATA = (
	'' => 0,
	'blafasdf' => 0,
	'http://fasfs.pl/' => 0,
	'fasdf../../../../' => 80,
	'fadfasdfsadfsadfasfd/bin/sh' => 100,
	'fadfasdfsadfsadfasfd/bin/zshfafa' => 100,
	'faadsf %s fasfasfd %s fasfdasf' => 80,

);

foreach my $data (keys %DATA) {
	print "$data -> " . Commons::validateData($data);
	print "\n";
	ok(Commons::validateData($data) == $DATA{$data});
}

exit 0;

# vim: set ft=perl:

