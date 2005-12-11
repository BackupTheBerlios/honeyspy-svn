#!/usr/bin/perl

package StderrTrapper;

use Log::Log4perl qw(:easy);

sub TIEHANDLE {
	my $class = shift;
	bless [], $class;
}

sub PRINT {
	my ($self, @data) = @_;
	$Log::Log4perl::caller_depth++;
	$logger->info(@data);
	$Log::Log4perl::caller_depth--;
}

