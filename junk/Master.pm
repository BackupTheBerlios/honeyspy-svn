#!/usr/bin/perl

package Master;

use strict;
use Node;

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
#	$self->{'socket'} = \*STDOUT;
#  ...

	return $self;
}

sub info() {
	$logger->debug("Jestem master ${\($_[0]->{name})}\n");
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
	$logger->debug("Destruktor Mastera ${\($_[0]->{'name'})}\n");
}


sub sendToPeer {
	my ($sock, $serialized) = (shift, freeze [@_]);
	print $sock pack('N', length($serialized));
	print $sock $serialized;
	print "wysylam\n";
}

sub run {
	my $self = shift;

	$logger->info("Starting master server " . $self->{'name'});
	$logger->debug("Entering main loop - master " . $self->{'name'});

	my $main_sock;
	if(!($main_sock = IO::Socket::SSL->new(
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
		$logger->fatal("unable to create socket: ", &IO::Socket::SSL::errstr, ", $!\n");
		exit(1);
	}
	$self->{'main_sock'} = $main_sock;
	$self->{'r_set'}->add($main_sock);

	$self->{'r_handlers'}{$main_sock} = \&accept_client;

	local $| = 1;

	$SIG{INT} = sub {
		$logger->info("Caught SIGINT.");
		close $main_sock;
		$logger->info("Closed main socket.");
		exit(0);
	};

	$self->SUPER::run();

}

sub accept_client {
	my $self = shift;

	$logger->info("Client connected.");
	my $client = $self->{'main_sock'}->accept();
	$self->{'w_set'}->add($client);
	$self->{'r_set'}->add($client);
	$self->{'w_handlers'}{$client} = \&serve_client;
	$self->{'r_handlers'}{$client} = \&read_from_client;
}

sub read_from_client {
	my($self, $sock) = @_;
	
	if ($sock->peek(undef, 1) == 0) {
		$self->{'w_set'}->remove($sock);
		$self->{'r_set'}->remove($sock);
		delete $self->{'w_handlers'}{$sock};
		delete $self->{'r_handlers'}{$sock};
		$logger->info("Sensor closed connection");
	}
}

sub serve_client {
	my($self, $sock) = @_;

	$logger->info("Sending data to client.");
	print $sock "Hello, my dear client.\n";
	$self->{'w_set'}->remove($sock);
#	close $sock;
}

1;

