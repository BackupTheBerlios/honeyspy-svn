#!/usr/bin/perl

package Master;

use strict;
use Carp;
use Node;
use Sensor;

use Log::Log4perl (':easy');
use Storable qw(nstore_fd freeze);
use IO::Socket::SSL;

require Exporter;
our @ISA = qw(Exporter Node);
our @EXPORT = ();


my $logger = get_logger();

#
# Master powinien miec atrybuty (oprocz dzidziczonych)
# 	server_sock
# 	sensor_sockets
# 	sensors
#

sub new($) {
	$logger->debug("konstruktor Mastera\n");

	my $class = ref($_[0]) || $_[0];
	my $self = $class->SUPER::new(@_[1..$#_]);

	$self->{'mode'} = 'master';
	$self->{'sensors'} = {};
#	$self->{'socket'} = \*STDOUT;
#  ...

	return $self;
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
#	$logger->debug("Destruktor Mastera\n");
}


sub run {
	my $self = shift;

	$logger->info("Starting master server " . $self->{'name'});

	my $listen_sock;
	if(!($listen_sock = IO::Socket::SSL->new(
				Listen => 5,
				LocalAddr => 'localhost',
				LocalPort => 9000,
				Proto     => 'tcp',
				Reuse     => 1,

				SSL_key_file => '../certs/master-key.pem',
				SSL_cert_file => '../certs/master-cert.pem',
				SSL_ca_file => '../certs/master-cert.pem',

				SSL_verify_mode => 0x01,
			)) ) {
		$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, ", $!\n");
		exit(1);
	}
	$self->{'listen_sock'} = $listen_sock;
	$self->addfh($listen_sock, 'r');

	$SIG{INT} = sub {
		$logger->info("Caught SIGINT.");
		close $listen_sock;
		$logger->info("Closed main socket.");
		exit(0);
	};

	$self->{'r_handlers'}{$listen_sock} = sub {
		$self->accept_client();
	};

	# Glowna petla wezla sieci
	$self->SUPER::run();

}


sub remove_sensor {
	my ($self, $sensor) = @_;
	$logger->debug('Removing sensor ' . $sensor->{'name'});

	delete $self->{'sensors'}{$sensor->{'socket'}};
	delete $self->{'sensors'}{$sensor->{'name'}};
	$self->removefh($sensor->{'socket'});
	close $sensor->{'socket'};
}


#
# Obsluga klienta ktory sie polaczyl
# Uczynienie z niego Sensora
#
sub accept_client {
	my ($self) = @_;

	my $socket = $self->{'listen_sock'}->accept();
	return unless $socket;
	$logger->info("Client connected from " . $socket->peerhost);

	my $authorized = 0;
	my ($subject_name, $issuer_name);
	if ($socket) {
		$subject_name = $socket->peer_certificate("subject");
		$issuer_name = $socket->peer_certificate("issuer");
		$authorized = 1 if ($subject_name && $issuer_name);
	}
	if (!$authorized) {
		$logger->info("Unauthorized connection dropped");
		return;
	}

	my $client_name = $subject_name;
	for ($client_name) {
		s'.*CN='';
		s'/.*'';
	}

	if ($client_name eq 'admin') {
		$logger->info("Administrator connected from " . $socket->peerhost);
		$self->_configure_master($socket);
		return;
	}

	if (exists($self->{'sensors'}{$client_name})) {
		$logger->warn("Sensor $client_name is already connected!");
		$logger->warn("Dropping connection.");
		return;
	}

	$logger->info("Sensor $client_name joined the network");

	my $sensor = new Sensor({
			name => $client_name,
			socket => $socket,
			master => $self,
		});
	$self->{'sensors'}{$client_name} = $sensor;
	$self->{'sensors'}{$socket} = $sensor;

	$self->{'w_handlers'}{$socket} = sub {
		$sensor->write();
	};
	$self->{'r_handlers'}{$socket} = sub {
		$sensor->read();
	};
	$logger->debug("Added $socket to select sets");
	$self->addfh($socket, 'rw');
}


1;

