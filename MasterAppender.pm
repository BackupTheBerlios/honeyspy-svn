#!/usr/bin/perl -w

use strict;

package MasterAppender;

sub new {
	my ($class, @options) = @_;

	print "MyAppender kons\n";

	my $self = {@options};

	bless $self, $class;
}

sub name {
	return 'honeyspy';
}

sub log {
	my ($self, @data) = @_;
	local $" = "|";
	print "Logujê -> @data\n";
	Node::sendDataToSocket($self->{'socket'}, 'log', @data);
}


1;

