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
# 	deskryptor gniazda
#

sub new($) {
	$logger->debug("konstruktor\n");

	my $class = ref($_[0]) or $_[0];
	my $self = {
		'name' => $_[1],
		'socket' => \*STDOUT,
	};
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

