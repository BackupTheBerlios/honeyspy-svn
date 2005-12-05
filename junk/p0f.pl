#!/usr/bin/perl -w
#
# HoneySpy p0f Proof-of-Concept
#

use strict;

use Net::P0f;

close STDERR;

$| = 1;

my $p0f = Net::P0f->new(
	interface => 'any',
	promiscuous => 1,
	detection_mode => 0,
#	fuzzy => 1,
	promiscuous => 1,
#	masquerade_detection => 1
);

$SIG{INT} = sub {
	exit 0;
};

#sleep 10;


for (;;) {
	print "Starting...\n";
	$p0f->loop(
		count => 1000,
		callback => \&process_packet,
	);
}

sub process_packet  {
	my ($self, $header, $os_info, $link_info) = @_;

	return if $os_info->{genre} eq 'UNKNOWN';

	print "$header->{ip_src} is probably running: ";
	print "$os_info->{genre} ($os_info->{details}), ";
	print "uptime: $os_info->{uptime} hours (?)\n";
}

