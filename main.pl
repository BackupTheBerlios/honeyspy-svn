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

Log::Log4perl::init('log4perl.conf');


my($master_mode, $config, $help);

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

