#!/usr/bin/perl -w

use strict;

use Sensor;

my $s1 = Sensor::new('sensor1');

print $s1->getName() . "\n";


my %sensors;
$sensors{$s1->getName()} = $s1;


$sensors{'sensor1'}->setFingerprint('192.168.15.19', 'Tru64');


print "\n";

