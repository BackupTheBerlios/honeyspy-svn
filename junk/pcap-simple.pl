#!/usr/bin/perl -w

use strict;
use Net::Pcap;
use NetPacket::IP;
use NetPacket::Ethernet qw(:strip);
use NetPacket::Ethernet;

use Net::Packet::ETH;


my $err;
my $pcap = Net::Pcap::open_live('any', 512, 1, 0, \$err);
$pcap or die $err;

print "wainting for packets...\n";
Net::Pcap::loop($pcap, -1, \&callback, '');

sub callback {
	my ($user_data, $hdr, $pkt) = @_;

	$pkt =~ s/^.{6}//;
	my $eth = Net::Packet::ETH->new(raw=>$pkt);
	print $eth->{'dst'} . "\n";

	my $dump = $pkt;
	$dump =~ s/(.)/sprintf('%02X', ord($1))/ges;
	print "$dump\n";
	print "-------\n";
	return;

	my $eth_obj = NetPacket::Ethernet->decode($pkt);
	print $eth_obj->{'src_mac'} . "\n";

	my $dump = $pkt;
	$dump =~ s/(.)/sprintf('%02X', ord($1))/ges;
	print "$dump\n-\n";

	$dump = $eth_obj->{'data'};
	$dump =~ s/(.)/sprintf('%02X', ord($1))/ges;
	print "$dump\n";

	my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
	print "src addr: " . $ip_obj->{'src_ip'} . "\n";

	print "-------\n";
}


