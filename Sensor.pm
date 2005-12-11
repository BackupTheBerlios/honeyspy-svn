#!/usr/bin/perl

package Sensor;

use Log::Log4perl (':easy');

use Storable qw(freeze thaw);
use Node;

require Exporter;
@ISA = qw(Exporter);
# (nie wolno eksportowac metod)
# @EXPORT = qw(sendToPeer recvFromPeer);

my $logger = get_logger();

#
# Sensor powinien miec atrybuty
# 	nazwa
# 	uchwyt gniazda (gniazda do sensora! nie mastera)
# 	referencja do obiekty klasy Master
#

sub new($) {
	$logger->debug("konstruktor\n");

	my $class = ref($_[0]) || $_[0];
	my $self = {
		'name' => undef,
		'socket' => undef,
		'master' => undef,
		'command_in_progress' => 0,
	};


	if (ref($_[1]) eq 'HASH')  {
		foreach my $attr qw(name socket master) {
			$self->{$attr} = $_[1]->{$attr} if defined $_[1]->{$attr};
		}
	}
	else {
		$self->{'name'} = $_[1];
	}

	return bless $self, $class;
}

sub info() {
	$logger->debug("Jestem sensor ${\($_[0]->{name})}\n");
}

#
# XXX
# Akcesory i modifykatory powinny byæ robione automatycznie
# [automatyczna modifikacja wpisów w przestrzeni nazw modu³u]
#
sub getName() {
	return shift->{'name'};
}


#
# Czyta komunikat od sensora (sa dane)
#
sub read {
	my ($self, $what) = @_;
	my ($sock) = $self->{'socket'};
	$logger->debug("Reading data from sensor");

	do {
		if ($sock->peek(undef, 1) == 0) {
			$logger->info("Sensor closed connection");
			$self->{'master'}->remove_sensor($self);
			return -1;
		}

		my ($type, @data) = $self->recvFromPeer();
		if ($type eq 'ret') {
			return @data;
		}
		elsif ($type eq 'log') {
			$logger->info(@data);
		}
		else {
			$logger->fatal("It shouldn't happen. Broken protocol! :(");
			return -2;
		}
	} while ($what && $what eq 'return_code');
}

#
# Pisze dane do sensora (gniazdo gotowe)
# XXX istotnie nie uzywamy juz tego
#
sub write {
	my ($self) = @_;
	my ($sock) = $self->{'socket'};
	$logger->debug("Writing data to sensor");

#	$self->sendToPeer('info', 0);
#	$self->{'master'}{'r_handlers'}{$sock} = sub {
#		if ($self->read) {
#			my $res = $self->recvFromPeer();
#			$logger->info("Sensor replied: $res");
#			$self->{'master'}->_removefh($sock, 'w');
#		}
#	};

	$self->{'master'}->_removefh($self->{'socket'}, 'w');
}


sub AUTOLOAD {
	$logger->debug("I should try tu ron $AUTOLOAD via RPC:\n");
	shift->call($AUTOLOAD, wantarray, @_);
}


#
# XXX
# Wywo³uje zdalnie na tym sensorze podan± funkcjê
#
sub call {
	my ($self, $name, $arrayctx, @args) = @_;
	my $sensor = $self->{'name'};
	local $" = ',';
	$logger->debug("I'm running function $name(@args) on $sensor sensor in "
		. ($arrayctx ? 'list' : 'scalar') . " context\n");

	$self->sendToPeer($name, $arrayctx, @args);
	$self->{'master'}->_removefh($self->{'socket'}, 'w');
	$self->{'command_in_progress'} = 1;
}

sub DESTROY {
	$logger->debug("Destruktor Sensora ${\($_[0]->{'name'})}\n");
}


sub sendToPeer {
	my ($self) = shift;
	my $sock = $self->{'socket'};

	return Node::sendDataToSocket($sock, @_);
}

sub recvFromPeer {
	my ($self) = @_;
	my $sock = $self->{'socket'};
	my $buf;

	sysread($sock, $buf, 4);
	my $len = unpack('N', $buf);
	sysread($sock, $buf, $len);
	my @resp;
	eval {
		@resp = @{thaw($buf)};
	};
	for ($@) {
		if (/Magic number checking on storable string failed/) {
			$logger->error("Wrong data received from sensor.");
			return;
		}
	}
	local $" = "\n   -> ";
	$logger->debug("Received data from Sensor:\n   -> @resp\n");
	return @resp;
}

1;

