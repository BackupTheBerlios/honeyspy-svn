#!/usr/bin/perl -w

use strict;
use lib '.';

use Log::Log4perl;

Log::Log4perl->init('log4perl.conf');

my $logger = Log::Log4perl->get_logger('blah');

$logger->debug('blah', 'bum');

