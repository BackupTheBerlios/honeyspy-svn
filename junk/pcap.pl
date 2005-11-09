#!/usr/bin/perl -w

use strict;

use Net::Pcap;
use Net::Packet;
use NetPacket::IP;
use NetPacket::Ethernet qw(:strip);
use IO::Select;

sub callback {
	local $" = "\n";
	print "--\n";
	print "$_[0]\n";
	my %hdr = %{$_[1]};
	foreach (keys %hdr) {
		print "$_ => $hdr{$_}\n";
	}
	print "--\n";
	my $ip_obj = NetPacket::IP->decode(eth_strip($_[2]));
	print "src ip: " . $ip_obj->{'src_ip'} . "\n";
	print "dst ip: " . $ip_obj->{'dest_ip'} . "\n";
	print "\n";
}

my $err;

my $dev = Net::Pcap::lookupdev(\$err);
my $pcap;

if ($dev) {
	print "$dev\n";
	$pcap = Net::Pcap::open_live('any', 100, 1, 0, \$err);
	print "$pcap\n";
	print "datalink: " . Net::Pcap::datalink($pcap) . "\n";
}
else {
	print "$err\n";
}

my $fno = Net::Pcap::fileno($pcap);
my $filter = 'icmp';
my $filter2;
Net::Pcap::compile($pcap, \$filter2, $filter, 1, '16') or print "filter compiled\n";
Net::Pcap::setfilter($pcap, $filter2);


print "$fno\n";

print "waiting\n";

#
# W ogólno¶ci mo¿e to sprawiaæ problemy na systemach BSD (zobacz w manualu).
# Istnieje obej¶cie, które nie dzia³a na FreeBSD > 4.3
# Ale na FreeBSD > 4.7 obej¶cie nie jest potrzebne, bo wszystko dzia³a
#

my $r_set = IO::Select->new();
$r_set->add($fno);

for (;;) {
	my @ready = IO::Select->select($r_set);
	if (!@ready) {
		print "error: $!\n";
		exit 1;
	}


	Net::Pcap::loop($pcap, 1, \&callback, 'aa');
	print "got it\n";
}

Net::Pcap::close($pcap);

exit;


