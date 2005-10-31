#!/usr/bin/perl -w

use Log::Log4perl (':easy');
Log::Log4perl->easy_init($DEBUG);

use strict;
use Master;


my $master = Master->new('laptop');
print $master . "\n";

$master->run();


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

