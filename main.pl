#!/usr/bin/perl -w

use strict;

use Log::Log4perl (':easy');
use Getopt::Long;
use Master;
use Node;

Log::Log4perl->easy_init($DEBUG);

my($master_mode, $config);

if (!GetOptions(
	'master|m' => \$master_mode,
	'config|c=s' => \$config,
) || !defined $config) {
	print "Usage:\n\t$0 [-m] -c <config_file>\n\n";
	exit 1;
}

my $node = $master_mode ?
	Master->new($config) : Node->new($config);

$node->run();

