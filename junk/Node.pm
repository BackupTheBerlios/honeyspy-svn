#!/usr/bin/perl

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use Storable qw(nstore_fd freeze);

require Exporter;
our @ISA = qw(Exporter);
# (nie wolno eksportowac metod)

my $logger = get_logger();

our $CORRECT_CERT;
*CORRECT_CERT =
	\"/C=PL/O=HoneySpy network/OU=Master Server/CN=Master";

#
# Wezel powinien miec atrybuty
# 	nazwa
# 	tryb [master lub sensor]
# 	deskryptor gniazda
# 	lista umiejetnosci
# 	lista interfejsow
# 	lista portow
# 	lista uchwytów plików: gotowych do odczytu, zapisu, wyj±tku
#

sub new($) {
	$logger->debug("konstruktor Node\n");

	my $class = ref($_[0]) || $_[0];
	my $self = {
		'name' => $_[1],
		'socket' => \*STDOUT,
		'mode' => 'sensor',
		'abilites' => [],
		'interfaces' => [],
		'ports' => [],
		'r_set' => new IO::Select(),
		'w_set' => new IO::Select(),
		'e_set' => new IO::Select(),
		'r_handlers' => {},
		'w_handlers' => {},
		'e_handlers' => {},
	};
	return bless $self, $class;
}


#
# XXX
# Akcesory i modifykatory powinny byæ robione automatycznie
# [automatyczna modifikacja wpisów w przestrzeni nazw modu³u]
#
sub getName() {
	return shift->{'name'};
}


sub DESTROY {
	$logger->debug("Node ${\($_[0]->{'name'})} destructor\n");
}

sub kill {
	$logger->info('Node is going down');
	exit 0;
}

sub setFingerprint {
	my ($addr, $os) = @_;
	$logger->info("Setting $os fingerprint on $addr");
}

sub delFingerprint {
	my ($addr) = @_;
	$logger->info("Disabling fingerprint mangling on $addr");
}

sub setMAC {
	my ($addr, $mac) = @_;
	$logger->info("Setting $mac address on $addr");
}

sub delMAC {
	my ($addr) = @_;
	$logger->info("Disabling MAC mangling on $addr");
}

sub sendToPeer {
	my ($sock, $serialized) = (shift, freeze [@_]);
	print $sock pack('N', length($serialized));
	print $sock $serialized;
	print "wysylam\n";
}

sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});

	my $master;
	if ($self->{'mode'} eq 'sensor') {
		if(!($master = IO::Socket::SSL->new( PeerAddr => 'localhost',
					PeerPort => '9000',
					Proto    => 'tcp',
					SSL_use_cert => 1,

					SSL_key_file => '../certs/sensor1-key.pem',
					SSL_cert_file => '../certs/sensor1-cert.pem',
					SSL_ca_file => '../certs/master-cert.pem',

					SSL_verify_mode => 0x01,
				))) {
			$logger->fatal("unable to create socket: ", &IO::Socket::SSL::errstr, ", $!\n");
			exit(1);
		}
		my ($subject_name, $issuer_name, $cipher, $trusted_master);
		$trusted_master = 0;
		if( ref($master) eq "IO::Socket::SSL") {
			$subject_name = $master->peer_certificate("subject");
			$issuer_name = $master->peer_certificate("issuer");
			$cipher = $master->get_cipher();

			$logger->debug("Certificate's subject: $subject_name");
			$logger->debug("Certificate's issuer: $issuer_name");

			if ($subject_name eq $CORRECT_CERT
				&& $issuer_name eq $CORRECT_CERT) {
					$trusted_master = 1;
			}
		}
		if (!$trusted_master) {
			$logger->fatal("My master doesn't have correct certificate!");
			exit(1);
		}
		$logger->info("Certificate recognized.");
		$logger->debug("Using cipher: $cipher");

		$self->{'r_set'}->add($master);
		$self->{'e_set'}->add($master);
		$self->{'r_handlers'}{$master} = \&process_command;
	}


	$logger->debug("Entering main loop - node " . $self->{'name'});
	for (;;) {
		$logger->debug("Waiting on select(2) syscall...");

		my ($r_ready, $w_ready, $e_ready) =
			IO::Select->select(
				$self->{'r_set'}, $self->{'w_set'}, $self->{'e_set'});

		foreach my $fh (@$r_ready) {
			&{$self->{'r_handlers'}{$fh}}($self, $fh)
				if (exists($self->{'r_handlers'}{$fh}));
		}
		foreach my $fh (@$w_ready) {
			&{$self->{'w_handlers'}{$fh}}($self, $fh)
				if (exists($self->{'w_handlers'}{$fh}));
		}
	}
}

sub process_command {
	my ($self, $sock) = @_;
	$logger->debug("Processing data from server.");

	if ($sock->peek(undef, 1) == 0) {
		$logger->debug("My master closed connection.");
		$self->{'r_set'}->remove($sock);
		$self->{'e_set'}->remove($sock);
		close($sock);
	}
	else {
		my $msg = <$sock>;
		$logger->debug("Server send me: $msg");
	}
}

1;

