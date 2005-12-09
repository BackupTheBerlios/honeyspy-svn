#!/usr/bin/perl -w

use strict;

package MyAppender;

sub new {
	my ($class, @options) = @_;

	print "MyAppender kons\n";

	my $self = {};

	bless $self, $class;
}

sub log {
	shift;
	local $" = "|";
	print "Logujê -> @_\n";
}


1;

