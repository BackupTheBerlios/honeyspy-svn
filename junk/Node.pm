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

#
# Wezel powinien miec atrybuty
# 	nazwa
# 	deskryptor gniazda
# 	lista umiejetnosci
# 	lista interfejsow
# 	lista portow
#

sub new($) {
	$logger->debug("konstruktor Node\n");

	my $class = ref($_[0]) || $_[0];
	my $self = {
		'name' => $_[1],
		'socket' => \*STDOUT,
		'abilites' => [],
		'interfaces' => [],
		'ports' => [],
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

	$logger->debug("Entering main loop - node " . $self->{'name'});
	for (;;) {
		IO::Select->select();
	}
}

1;

