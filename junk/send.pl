#!/usr/bin/perl -w

use strict;

use Storable "nstore_fd";

$| = 1;

sleep 1;

my @t = (
	'nazwa_funkcji',
	1,
	'192.168.66.1',
	'amigaos'
);

nstore_fd(\@t, \*STDOUT);

sleep 3;

my @t2 = (
	'funkcja2',
	0,
	'217.113.230.246',
	'blabla',
	'x'
);

nstore_fd(\@t2, \*STDOUT);

