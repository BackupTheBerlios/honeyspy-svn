#!/usr/bin/perl -w

use strict;

use Storable 'fd_retrieve';

$| = 1;

print "czekam..\n";
my $ref = fd_retrieve(\*STDIN);
print "@$ref\n";

print "czekam..\n";
$ref = fd_retrieve(\*STDIN);
print "@$ref\n";

