#!/usr/bin/perl -w

use strict;

package MasterAppender;

sub new {
	my ($class, @options) = @_;

	my $self = {@options};

	bless $self, $class;
}

sub log {
	my ($self, @data) = @_;

	Node::sendDataToSocket($self->{'socket'}, 'log', @data);
}


1;

