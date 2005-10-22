#!/usr/bin/perl

package Sensor;
require Exporter;
@ISA = qw(Exporter);


sub new($) {
	print "konstruktor\n";
	my $self = {
		'name' => $_[0]
	};
	return bless $self;
}

sub info() {
	print "Jestem sensor\n";
}


sub getName() {
	return shift->{'name'};
}


1;

