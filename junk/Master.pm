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

#	$self{'socket'} = \*STDOUT;
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
		$logger->fatal("unable to create socket: ", &IO::Socket::SSL::errstr, "\n");
		exit(1);
	}


	my $r_set = new IO::Select($main_sock);
	my $w_set = new IO::Select($main_sock);

	$| = 1;
	while (1) {
		$logger->debug("Waiting for data...");
		my ($r_ready, $w_ready, $e_ready) = IO::Select->select($r_set, $w_set);
		foreach my $fh (@$r_ready) {
			if ($fh == $main_sock) {
				$logger->info("Client connected.");
				my $client = $main_sock->accept();
				$w_set->add($client);
			}
			else {
			}
		}
		foreach my $fh (@$w_ready) {
			if ($fh == $main_sock) {
				
			}
			else {
				print $fh "hello, client.\n";
				$w_set->remove($fh);
				close $fh;
			}
		}
	}

}


1;

