#!/usr/bin/perl -w
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


use strict;

use Log::Log4perl (':easy');
use Getopt::Long;
use Master;
use Node;

#Log::Log4perl->easy_init($DEBUG);

sub usage {
	my $exitcode = @_;
	print "\n";
	print "HoneySpy -- advance honeypot environment\n";
	print "Copyright (C) 2005 Robert Nowotniak\n";
	print "Copyright (C) 2005 Michal Wysokinski\n";
	print "\n";
	print "This program is free software; you can redistribute it and/or\n";
	print "modify it under the terms of the GNU General Public License\n";
	print "as published by the Free Software Foundation; either version 2\n";
	print "of the License, or (at your option) any later version.\n";
	print "\n";

	print "Usage:\n";
	print "\t$0 [-h|--help] [-m|--master] -c|--config <config_file>\n\n";
	exit $exitcode;
}

Log::Log4perl::init('log4perl.conf');


my($master_mode, $config, $help);

if (!GetOptions(
	'master|m'   => \$master_mode,
	'help|h'     => \$help,
	'config|c=s' => \$config,
)) {
	usage(1); 
}

if (!defined $config) {
	usage(1);
}

if ($help) {
	usage(0);
}

my $node = $master_mode ?
	Master->new($config) : Node->new($config);

$node->run();

