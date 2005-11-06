#!/usr/bin/perl -w

use strict;

use Log::Log4perl (':easy');
use Getopt::Long;
use Master;
use Node;

Log::Log4perl->easy_init($DEBUG);

my($master_mode);

GetOptions(
	'master|m' => \$master_mode
);

if ($#ARGV != 0) {
	print "Usage:\n\t$0 [-m] <node_name>\n\n";
	exit 1;
}

my $node_name = $ARGV[0];


if ($master_mode) {
	my $master = Master->new($node_name);
	print $master . "\n";
	$master->run();
}
else {
	my $node = Node->new($node_name);
	print $node . "\n";
	$node->run();
}


exit;

__END__

# 
# stare proby
# 

my $s1 = Sensor->new('sensor1');

print $s1->getName() . "\n";


my %sensors;
$sensors{$s1->getName()} = $s1;


$sensors{'sensor1'}->setFingerprint('192.168.15.19', 'Tru64');


print "\n";

