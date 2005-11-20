#!/usr/bin/perl -w

use strict;

use Sensor;
use IO::Socket::SSL;
use Term::ReadLine;
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

	SSL_key_file => '../certs/admin-key.enc',
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

print "\nConnection established\n";

my $prompt = '> ';
my $term = new Term::ReadLine 'HoneySpy console';

my $s = new Sensor({
	name => 'main',
	socket => $master,
});

print $prompt;
while (defined($_ = $term->readline($prompt))) {
	$term->addhistory($_) if /\S/;
	next unless ($_);
	my ($cmd, $args, @args) = ($_);
	if (/^(.*?)\s(.*)/) {
		($cmd, @args) = ($1, split(/\s*,\s*/, $2));
	}

	$s->sendToPeer($cmd, 1, @args);
	my @res = $s->recvFromPeer();

	print $prompt;
}

