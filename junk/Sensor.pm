#!/usr/bin/perl

package Sensor;

use Log::Log4perl (':easy');

use Storable qw(nstore_fd freeze);

require Exporter;
@ISA = qw(Exporter);
# (nie wolno eksportowac metod)
@EXPORT = ('sendToPeer');

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
		'socket' => \*STDOUT,
		'master' => undef,
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
	my ($self) = @_;
	my ($sock) = $self->{'socket'};
	$logger->debug("Reading data from sensor");

	if ($sock->peek(undef, 1) == 0) {
		$logger->info("Sensor closed connection");
		$self->{'master'}->removefh($sock, 'rwe');
	}
}

#
# Pisze dane do sensora (gniazdo gotowe)
#
sub write {
	my ($self) = @_;
	my ($sock) = $self->{'socket'};
	$logger->debug("Writing data to sensor");

	print $sock "Hello, my dear client.\n";
	$self->{'master'}->remove_sensor($self);
}


sub AUTOLOAD {
	$logger->debug("Powinienem sprobowac wywolac zdalnie $AUTOLOAD:\n");
	shift->call($AUTOLOAD, wantarray, @_);
}


#
# Wywo³uje zdalnie na tym sensorze podan± funkcjê
#
sub call {
	my ($self, $name, $arrayctx, @args) = @_;
	my $sensor = $self->{name};
	local $" = ',';
	$logger->debug("Wywo³ujê zdalnie na sensorze $sensor funkcje $name(@args) w kontekscie "
		. ($arrayctx ? 'listowym' : 'skalarnym') . "\n");

#	my $fh = $self->{socket};
#	my $serialized = freeze [$name, $arrayctx, @args];

#	print $fh pack('N', length($serialized));
#	print $fh $serialized;

	sendToPeer($self->{socket}, $name, $arrayctx, @args);
}

sub DESTROY {
	$logger->debug("Destruktor Sensora ${\($_[0]->{'name'})}\n");
}


sub sendToPeer {
	my ($sock, $serialized) = (shift, freeze [@_]);
	print $sock pack('N', length($serialized));
	print $sock $serialized;
	print "wysylam\n";
}


1;

