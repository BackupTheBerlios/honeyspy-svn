#!/usr/bin/perl -w

use strict;

use Sensor;

my $s1 = Sensor::new('sensor1');

print $s1->getName();

