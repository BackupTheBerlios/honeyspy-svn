#!/usr/bin/perl

package Sensor;

use Storable 'nstore_fd';

require Exporter;
@ISA = qw(Exporter);
# (nie wolno eksportowac metod)

#
# Sensor powinien miec atrybuty
# 	nazwa
# 	deskryptor gniazda
#

sub new($) {
	print "konstruktor\n";
	my $self = {
		'name' => $_[0],
		'socket' => \*STDOUT,
	};
	return bless $self;
}

sub info() {
	print "Jestem sensor ${\($_[0]->{name})}\n";
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
	print "Powinienem sprobowac wywolac zdalnie $AUTOLOAD:\n";
	shift->call($AUTOLOAD, defined wantarray, @_);
}


#
# Wywo³uje zdalnie na tym sensorze podan± funkcjê
#
sub call {
	my ($self, $name, $arrayctx, @args) = @_;
	my $sensor = $self->{name};
	local $" = ',';
	print "Wywo³ujê zdalnie na sensorze $sensor funkcje $name(@args) w kontekscie "
	. ($arrayctx ? 'listowym' : 'skalarnym') . "\n";

	nstore_fd([$name, $arrayctx, @args], $self->{socket});
}

sub DESTROY {
	print "Destruktor Sensora ${\($_[0]->{'name'})}\n";
}

1;

