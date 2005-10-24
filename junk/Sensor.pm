#!/usr/bin/perl

package Sensor;

use Log::Log4perl (':easy');

use Storable qw(nstore_fd freeze);

require Exporter;
@ISA = qw(Exporter);
# (nie wolno eksportowac metod)

my $logger = get_logger();

#
# Sensor powinien miec atrybuty
# 	nazwa
# 	deskryptor gniazda
#

sub new($) {
	$logger->debug("konstruktor\n");
	my $self = {
		'name' => $_[0],
		'socket' => \*STDOUT,
	};
	return bless $self;
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
	shift->call($AUTOLOAD, defined wantarray, @_);
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

	my $fh = $self->{socket};
	my $serialized = freeze [$name, $arrayctx, @args];
	print $fh pack('N', length($serialized));
	print $fh $serialized;
	#nstore_fd([$name, $arrayctx, @args], $fh);
#	$fh->flush();
#	$fh->flush();
}

sub DESTROY {
	$logger->debug("Destruktor Sensora ${\($_[0]->{'name'})}\n");
}

1;

