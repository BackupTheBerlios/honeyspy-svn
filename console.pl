#!/usr/bin/perl -w

use strict;

use Sensor;
use IO::Socket::SSL;
use Term::ReadLine;
use Log::Log4perl (':easy');
Log::Log4perl->easy_init($WARN);

use constant HISTORY_FILE => "$ENV{HOME}/.honeyspy_history";
use constant COMPLETION_LIST => [qw/
	getName
	getAbilities
	runOnNode
	getSensors
	kill

	addService
	delService

	addIPAlias
	delIPAlias
	getIPAlias

	getAvailableFingerprints
	setFingerprint
	delFingerprint

	setMAC
	getMAC
	delMAC

	enableP0f
	disableP0f

	enablePcap
	addFilter
	replaceFilters
	delFilter
	getFilter
/];


if ($#ARGV != 1) {
	print "Usage:\n\t$0 <host> <port>\n";
	exit 1;
}

my $logger = get_logger();

my $master = IO::Socket::SSL->new( PeerAddr => $ARGV[0],
	PeerPort => $ARGV[1],
	Proto    => 'tcp',
	SSL_use_cert => 1,

	SSL_key_file => 'certs/admin-key.enc',
	SSL_cert_file => 'certs/admin-cert.pem',
	SSL_ca_file => 'certs/master-cert.pem',

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
my $rl_attribs = $term->Attribs;
$rl_attribs->{'completion_entry_function'} = 
	$rl_attribs->{'list_completion_function'};
$rl_attribs->{'completion_word'} = COMPLETION_LIST;
$term->read_history(HISTORY_FILE)
 if -r HISTORY_FILE;


my $s = new Sensor({
	name => 'main',
	socket => $master,
});


print $prompt;
while (defined($_ = $term->readline($prompt))) {
	$term->addhistory($_) if /\S/;
	next unless ($_);

	my ($cmd, @args) = split(/\s+/);

	$s->sendToPeer($cmd, 1, @args);
	my @res = $s->read('return_code');

	local $" = "\n   -> ";
	print "@res\n";

	print $prompt;
}

system("touch " . HISTORY_FILE);
$term->append_history(100, HISTORY_FILE);

