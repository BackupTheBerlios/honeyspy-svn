#!/usr/bin/perl -w

use strict;

#
# tak chcia�bym obs�ugiwa� sie� honeypot�w
# tak powinni�my m�c pisa� skrypt obs�uguj�cy interfejs webowy
#

my $honeynet = new HoneyNet('127.0.0.1:9000');

$honeynet->getSensors();

$honeynet{'serw3'}->addService('10.0.15.19', 'tcp', '80', 'iis');

