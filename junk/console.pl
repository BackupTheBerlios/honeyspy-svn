#!/usr/bin/perl -w

use strict;

use Sensor;
use IO::Socket::SSL;
use Log::Log4perl (':easy');
Log::Log4perl->easy_init($DEBUG);

if ($#ARGV != 1) {
	print "Usage:\n\t$0 <host> <port>\n";
	exit 1;
}

my $logger = get_logger();

my $master = IO::Socket::SSL->new( PeerAddr => $ARGV[0],
	PeerPort => $ARGV[1],
	Proto    => 'tcp',
	SSL_use_cert => 1,

	SSL_key_file => '../certs/admin-key.pem',
	SSL_cert_file => '../certs/admin-cert.pem',
	SSL_ca_file => '../certs/master-cert.pem',

	SSL_verify_mode => 0x01);

if (!$master) { 
	$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, "\n");
	exit 1;
}

print <<EOF;
************************************************************
***            HoneySpy experimental console             ***
************************************************************
EOF

my $prompt = '> ';

print $prompt;
while (<STDIN>) {
	chomp;
	my ($cmd, @args) = ($_);
	if (/^(.*?)\s(.*)/) {
		($cmd, @args) = ($1, split(/\s/, $2));
	}

	Sensor::sendToPeer($master, $cmd, 1, @args);
	my @res = Sensor::recvFromPeer($master);

	print $prompt;
}

