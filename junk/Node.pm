#!/usr/bin/perl

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use Storable qw(nstore_fd freeze);
use IO::Socket::SSL; # qw(debug4);
use Carp;

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

		'abilites' => {},
		'interfaces' => [],
		'ports' => [],

		# Zbiory uchwytow plikow, ktore trzeba obserwowac
		'r_set' => new IO::Select(),
		'w_set' => new IO::Select(),
		'e_set' => new IO::Select(),

		# Handlery dla poszczegolnych uchwytow plikow
		'r_handlers' => {},
		'w_handlers' => {},
		'e_handlers' => {},

      'stimeout' => 2,
      'reconnect' => 4, # tyle sekund miedzy reconnect
      'connected' => 0
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

sub _connect_to_master {
   my($self) = @_;
	my $master;

	$logger->debug("Connecting to 127.0.0.1:9000...");
	$master = IO::Socket::SSL->new( PeerAddr => '127.0.0.1',
		PeerPort => '9000',
		Proto    => 'tcp',
		SSL_use_cert => 1,

		SSL_key_file => '../certs/sensor1-key.pem',
		SSL_cert_file => '../certs/sensor1-cert.pem',
		SSL_ca_file => '../certs/master-cert.pem',

		SSL_verify_mode => 0x01);
	if (!$master) {
		$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, "\n");
		return 0;
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
		$logger->fatal("Master doesn't have correct certificate!");
		exit(1);
	}
	$logger->info("Certificate recognized.");
	$logger->debug("Using cipher: $cipher");

	$self->addfh($master, 're');
	$self->{'r_handlers'}{$master} = \&process_command;

	$self->{'connected'} = 1;
	$self->{'master_sock'} = $master;
}


sub removefh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->remove($fh);
		delete $self->{$_.'_handlers'}{$fh};
	}
}


sub addfh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->add($fh);
	}
}


sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});

	if ($self->{'mode'} eq 'sensor') {
		while (!($self->_connect_to_master())) {
			my $delay = $self->{'reconnect'};
			$logger->info("Retrying in $delay seconds");
			select(undef, undef, undef, $delay);
		}
	}

	local $| = 1;

	$logger->debug("Entering main loop - node " . $self->{'name'});
	for (;;) {
		$logger->debug("Waiting on select(2) syscall...");

		$logger->debug("Write watched handles: " , $self->{'w_set'}->handles);
		my ($r_ready, $w_ready, $e_ready) =
			IO::Select->select(
				$self->{'r_set'}, $self->{'w_set'}, $self->{'e_set'},
				$self->{'stimeout'});

		if (!defined($r_ready)) {
			#
			# Na zadnym uchwycie nie bylo zdarzenia
			#
			$logger->debug("Timeout");
			if ($self->{'mode'} eq 'sensor') {
				if (! $self->{'connected'}) {
					$logger->debug("Trying to reconnect to my master");
					$self->_connect_to_master();
				}
			}
			next;
		}

		foreach my $fh (@$r_ready) {
			$logger->debug("Something in read ready set");

			if ($self->{'mode'} eq 'master') {
				if (exists($self->{'sensors'}{$fh})) {
					$self->{'sensors'}{$fh}->read();
				}
				elsif ($fh == $self->{'listen_sock'}) {
					$self->accept_client();
				}
				else {
					confess "Unknown filehandle in a set";
				}
			}
			else { # Sensor mode
				confess "Master socket should be the only filehandle here"
					unless $fh == $self->{'master_sock'};
				$self->process_command($fh);
			}

			next;
			&{$self->{'r_handlers'}{$fh}}($self, $fh)
				if (exists($self->{'r_handlers'}{$fh}));
		}
		foreach my $fh (@$w_ready) {
			$logger->debug("Something in write ready set");
			if (exists($self->{'sensors'}{$fh})) {
				$logger->debug($fh);
				$self->{'sensors'}{$fh}->write();
			}
			elsif ($self->{'mode'} eq 'master' && $fh == $self->{'listen_sock'}) {
				# NOT REACHABLE (?)
				$self->accept_client();
			}
			$logger->debug($fh);

			next;
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
		$self->removefh($sock, 're');
		$self->{'connected'} = 0;
		close($sock);
	}
	else {
		my $msg = <$sock>;
		$logger->debug("Server send me: $msg");
	}
}

1;

