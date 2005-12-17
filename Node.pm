#!/usr/bin/perl -T
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use MasterAppender;
use Storable qw(nstore_fd freeze thaw);
use IO::Socket::SSL;
use IO::Socket::INET;
use NetPacket::Ethernet qw(:strip);
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Net::Pcap;
use POSIX qw(setsid);
use Carp;
use Socket;
use IPC::Open2;

use Master;
use Commons;
use FHTrapper;

require Exporter;
our @ISA = qw(Exporter);

my $logger = get_logger();

use constant CORRECT_CERT =>
	"/C=PL/O=HoneySpy network/OU=Master Server/CN=Master";

use constant FINGERPRINTS_DIR => "fingerprints/";



#
# Konstruktor
#
sub new {
	my ($class,  $config_file) = 
		(ref($_[0]) || $_[0], $_[1]);

	$logger->debug("Node constructor\n");

	my $self = {
		'name' => 'unnamed',
		'master_sock' => undef,
		'mode' => 'sensor',
		'appender' => undef,

		# Atrybuty dzialania serwera
		'abilities' => {
			'p0f' => undef,         # rozpoznawanie zdalnego os
			'fingerprint' => undef, # falszowanie stosu
			'mac' => undef,         # falszowanie adresow mac
			'pcap' => undef,        # nasluchiwanie pakietow
			'ipalias' => undef,     # ip aliasy
		},
		'interfaces' => [],
		'ports' => {},             # dzialajace uslugi
											# "addr/proto/port" ->
											#	 {socket -> ..., script -> ..., args -> ...}
		'processes_spawned' => 0,
		'processes_limit' => 10,

		# Interfejs nasluchiwania (PCAP)
		'pcap' => undef,
		'pcap_filters' => [],
		'compiled_filter' => undef,

		# przypisane przez honeypota ip aliasy (ip -> interfejs)
		'ip_aliases' => {},

		# spoofowane adresy mac (ip -> mac)
		'spoofed_mac' => {},

		# falszowane charakterystyki stosu tcp/ip (ip -> os)
		'fingerprints' => {},
		'p0f_pid' => undef,
		'p0f_fh' => undef,
		'p0f_opts' => {
			'fuzzy' => '0',
			'promiscuous' => '1',
			'masq_detection' => '0',
			'mode' => '0',
		},

		# Handlery dla zdarzen na uchwytach plikow
		'r_handlers' => {},
		'w_handlers' => {},
		'e_handlers' => {},

		# Zbiory uchwytow plikow, ktore trzeba obserwowac
		'r_set' => new IO::Select(),
		'w_set' => new IO::Select(),
		'e_set' => new IO::Select(),

      'stimeout' => 3,
      'reconnect' => 4, # tyle sekund miedzy reconnect
      'connected' => 0
	};

	bless $self, $class;

	$self->readConfig($config_file)
		if defined $config_file;

	$self->_checkAbilities();

	$self->_initIPAliases()
		if $self->{'abilities'}{'ipaliases'};

	return $self;
}


################################################################################
# Metody prywatne
################################################################################

#
# XXX Mozna polepszyc to sprawdzanie (jest wstepna prosta wersja)
#
sub _checkAbilities {
	my ($self) = @_;
	$logger->debug("Checking my abilities...");
	
	$self->{'abilities'}{'ipaliases'} = 0;
	$self->{'abilities'}{'p0f'} = 0;
	$self->{'abilities'}{'fingerprint'} = 0;
	$self->{'abilities'}{'pcap'} = 0;
	$self->{'abilities'}{'mac'} = 0;

	# IP Aliasy
	$self->{'abilities'}{'ipaliases'} = 1 if ! $>;

	# p0f
	foreach (split(/:/, $ENV{'PATH'})) {
		if (-x "$_/p0f") {
			$self->{'abilities'}{'p0f'} = 1;
			last;
		}
	}

	# fingerprint
	$self->{'abilities'}{'fingerprint'} = 1 if ! $>;

	# pcap
	my $err;
	Net::Pcap::open_live('any', 512, 1, 0, \$err);
	$self->{'abilities'}{'pcap'} = 1 if (! $err);

	# mac
	my ($ebtables, $arptables, $ifconfig);
	foreach (split(/:/, $ENV{'PATH'})) {
		$ebtables = 1 if -x "$_/ebtables";
		$arptables = 1 if -x "$_/arptables";
		$ifconfig = 1 if -x "$_/ifconfig";
		last if $ebtables && $arptables && $ifconfig;
	}
	$self->{'abilities'}{'mac'} = 1 if $ebtables && $arptables && $ifconfig;

	my @abilities = grep {$self->{'abilities'}{$_}} keys %{$self->{'abilities'}};
	local $" = ',';
	no warnings;
	$logger->debug("My abilities are: @abilities");
}

sub _initIPAliases {
	my ($self) = @_;
	
	my $ifname;
	foreach (qx/ifconfig -a/) {
		if (/^(honey:\d+)/) {
			$ifname = $1;
		}
		elsif ($ifname && /inet addr:(\S+)\s/) {
			$self->{'ip_aliases'}{$1} = $ifname;
			undef $ifname;
		}
	}
}

sub _updateArpTables {
	my ($self) = @_;

	system('ebtables -t nat -F PREROUTING;'
	. 'arptables -t nat -F POSTROUTING;'
	. 'arptables -t mangle -F OUTPUT;') >> 8 == 0
		or return "Couldn't clean ebtables and arptables rules";

	while ((my ($ip, $mac) = each(%{$self->{'spoofed_mac'}}))) {

		next unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		next unless $mac =~ /([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}/;

		system("arptables -t mangle -A OUTPUT --h-length 6 -o honey "
		. "-s $ip -j mangle --mangle-mac-s $mac") >> 8 == 0
			or return "Couldn't set arptables rule ($ip -> $mac)";

		system("ebtables -t nat -A PREROUTING -d $mac -j redirect") >> 8 == 0
			or return "Couldn't set ebtables rule (to redirect $mac)";

		system("ebtables -t nat -A POSTROUTING -p ipv4 --ip-src $ip "
		. "-j snat --to-source $mac") >> 8 == 0
			or return "Couldn't set ebtables rule ($mac POSTROUTING entry)";
	}

	return 0;
}

sub _searchForRegexInCmd {
	my ($self, $regex, $cmd) = @_;
	foreach (qx/$cmd/) {
		return 1 if (/$regex/);
	}
	return 0;
}

sub _updateIpTables {
	my ($self) = @_;

	my ($honeyspy_in_output, $honeyspy_in_prerouting) = (
		$self->_searchForRegexInCmd('^honeyspy\W', 'iptables -t mangle -L OUTPUT -n'),
		$self->_searchForRegexInCmd('^honeyspy\W', 'iptables -t mangle -L PREROUTING -n')
	);

	system('iptables -t mangle -N honeyspy')
		unless ($honeyspy_in_output or $honeyspy_in_prerouting);
	system('iptables -t mangle -F honeyspy');

	system('iptables -t mangle -I OUTPUT 1 -j honeyspy')
		unless ($honeyspy_in_output);
	system('iptables -t mangle -I PREROUTING 1 -j honeyspy')
		unless ($honeyspy_in_prerouting);

	while ((my ($ip, $os) = each(%{$self->{'fingerprints'}}))) {
		next unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		next unless $os =~ /^[[:alnum:]\._\-]+$/;

		system("iptables -t mangle -A honeyspy -d $ip -j PERS "
		. "--tweak dst --local --conf " . FINGERPRINTS_DIR . "/$os.conf") >> 8 == 0
			or return "Couldn't set $os fingerprint on $ip";
		system("iptables -t mangle -A honeyspy -s $ip -j PERS "
		. "--tweak src --local --conf " . FINGERPRINTS_DIR . "/$os.conf") >> 8 == 0
			or return "Couldn't set $os fingerprint on $ip";
	}

	return 0;
}

sub _compileFilter {
	my ($self) = @_;
	my $compiled;

	return unless @{$self->{'pcap_filters'}} && $self->{'pcap'};

	# sprawdzic kazda regule po kolei
	foreach (@{$self->{'pcap_filters'}}) {
		my $err = Net::Pcap::compile($self->{'pcap'}, \$compiled, $_, 1, 0);
		if ($err) {
			$err = "Error in rule: $_";
			$logger->error($err);
			return $err;
		}
	}

	if (@{$self->{'pcap_filters'}} > 1) {
		# zrobic alternatywe logiczna wszystkich regul
		my @filters = @{$self->{'pcap_filters'}};
		my $sum = $filters[0];
		$sum = "($sum) or ($_)" foreach @filters[1..$#filters];
		my $err = '';
		$err = Net::Pcap::compile($self->{'pcap'}, \$compiled, $sum, 1, 0);
		if ($err) {
			$err = "Error in rules sum: $sum. " . Net::Pcap::geterr($self->{'pcap'});
			$logger->error($err);
			return $err;
		}
	}

	Net::Pcap::setfilter($self->{'pcap'}, $compiled);

	return 0;
}

sub _setupPcap {
	my ($self) = @_;
	my $err;
	
	$self->{'pcap'} =
		Net::Pcap::open_live('any', 512, 1, 0, \$err);
	$logger->error($err) if $err;

	$logger->debug("pcap datalink: " . Net::Pcap::datalink($self->{'pcap'}));

	$self->_compileFilter();
}

sub _pcapPacket {
	my ($user_data, $hdr, $pkt) = @_;

	my $eth_obj = NetPacket::Ethernet->decode($pkt);
	my $msg = "Packet matched PCAP rule.";
	$msg .= " src mac: " . $eth_obj->{'src_mac'};
	$msg .= " dst mac: " . $eth_obj->{'dst_mac'}
		if defined($eth_obj->{'dst_mac'});

	#my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
	my $ip_obj = NetPacket::IP->decode(substr($eth_obj->{'data'}, 2));
	$msg .= " | ";
	$msg .= 'src:' . $ip_obj->{'src_ip'};
	$msg .= ' dst:' . $ip_obj->{'dest_ip'};
	$msg .= ' ipver:' . $ip_obj->{'ver'};
	$msg .= ' tos:' . $ip_obj->{'tos'};
	$msg .= ' len:' . $ip_obj->{'len'};
	$msg .= ' id:' . $ip_obj->{'id'};
	$msg .= ' proto:' . getprotobynumber($ip_obj->{'proto'});
	$msg .= ' flags:' . $ip_obj->{'flags'};

	if ($ip_obj->{'proto'} == getprotobyname('tcp')) {
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{'data'});
		$msg .= ' | tcp';
		$msg .= ' src port: ' . $tcp_obj->{'src_port'};
		$msg .= ' dst port: ' . $tcp_obj->{'dest_port'};
	}

	$logger->info($msg);
}

#
# Jesli funkcja wywolana przez te funkcje zwrocila
# cokolwiek defined, to _callFunction odesle to jako odpowiedz
# do mastera.
# Jesli funkcja wywolana zwrocila undef, to znaczy,
# zeby nie odsylac, bo moze funkcja sama ustawi(la) w_handler
#
sub _callFunction {
	my ($self, $function, $arrayctx, @args) = @_;
	my @result;
	my $local = 1;

	eval {
		no strict 'refs';
		unshift(@args, $self);
		if ($arrayctx) {
			@result = @{[&{*{$function}}(@args)]};
		}
		else {
			@result = (scalar &{*{$function}}(@args));
		}
	};
	for ($@) {
		last unless ($@);

		if (/Undefined subroutine/) {
			$result[0] = "No such function ($function) on remote side";
			last;
		}
		else {
			$result[0] = "Error $_ during excecution of remote called function";
		}

		$logger->error($result[0]);
	}

	if (defined($result[0])) {
		my $master_sock = $self->{'master_sock'};
		$self->{'w_handlers'}{$master_sock} = sub {
			Commons::sendDataToSocket($master_sock, 'ret', @result);
			$self->_removefh($master_sock, 'w');
		};
		$self->_addfh($master_sock, 'w');
	}

	return 0;

	return @result;
}

sub _configure_master_connection {
   my ($self, $master) = @_;
	
	$self->_addfh($master, 're');
	$self->{'r_handlers'}{$master} = sub {
		$self->process_command($master);
	};

	$self->{'connected'} = 1;
	$self->{'master_sock'} = $master;

	my $appender = Log::Log4perl::Appender->new(
		'MasterAppender',
		name => 'MasterAppender',
		socket => $self->{'master_sock'}
	);

	my $layout = Log::Log4perl::Layout::PatternLayout->new("%m%n");
	$appender->layout($layout);
	$logger->add_appender($appender);
	$self->{'appender'} = $appender;
}


sub _connect_to_master {
   my ($self) = @_;
	my $master;

	$logger->debug("Connecting to $self->{'master_addr'}:$self->{'master_port'}...");
	$master = IO::Socket::SSL->new(
		PeerAddr => $self->{'master_addr'},
		PeerPort => $self->{'master_port'},
		Proto    => 'tcp',
		SSL_use_cert => 1,

		SSL_key_file => $self->{'ssl_key'},
		SSL_cert_file => $self->{'ssl_cert'},

		SSL_ca_file => $self->{'ca_file'},

		SSL_verify_mode => 0x01);
	if (!$master) {
		$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, "\n");
		return 0;
	}
	my ($subject_name, $issuer_name, $cipher, $trusted_master);
	$trusted_master = 0;
	if(ref($master) eq "IO::Socket::SSL") {
		$subject_name = $master->peer_certificate("subject");
		$issuer_name = $master->peer_certificate("issuer");
		$cipher = $master->get_cipher();

		$logger->debug("Certificate's subject: $subject_name");
		$logger->debug("Certificate's issuer: $issuer_name");

		if ($subject_name eq CORRECT_CERT
			&& $issuer_name eq CORRECT_CERT) {
				$trusted_master = 1;
		}
	}
	if (!$trusted_master) {
		$logger->fatal("Master doesn't have correct certificate!");
		exit(1);
	}
	$logger->info("Certificate recognized.");
	$logger->debug("Using cipher: $cipher");

	$self->_configure_master_connection($master);
}

sub _removefh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->remove($fh);
		delete $self->{$_.'_handlers'}{$fh};
	}
}

sub _addfh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->add($fh);
	}
}


################################################################################
# Metody publiczne
################################################################################


#
# Wczytanie konfiguracji z pliku
#
sub readConfig {
	my ($self, $file) = @_;
	return "No config file given." unless $file;

	my $config = do $file;

	return "Couldn't parse config file ($!, $@)."
		unless defined $config;

	my @config_params = qw {
		name
		master_addr
		master_port
		listen_addr
		listen_port
		ca_file
		ssl_key
		ssl_cert
	};

	foreach (@config_params) {
		$self->{$_} = $config->{$_}
			if defined $config->{$_};
	}

	return 0;
}


#
# U¿ywane g³ównie do testów RPC
#
sub getAbilities {
	my ($self) = @_;
	return %{$self->{'abilities'}};
}

sub getName() {
	my ($self) = @_;
	return $self->{'name'};
}


#
# Pobranie listy sensorów podleg³ych temu wêz³owi
# (czyli ³±cznie z nim samym)
#
sub getSensors() {
	my ($self) = @_;
	my @names = $self->{'name'};
	my %sensors = ();

	foreach (keys %{$self->{'sensors'}}) {
		if (! exists($sensors{$self->{'sensors'}{$_}})) {
			push @names, $self->{'sensors'}{$_}{'name'};
			$sensors{$self->{'sensors'}{$_}} = 1;
		}
	}

	return @names;
}

sub info {
	my $msg = "I'm ${\($_[0]->{name})} node";
	$logger->debug($msg);
	return $msg;
}

sub kill {
	$logger->info('Node is going down in a moment');
	$SIG{'ALRM'} = sub {
		exit 0;
	};
	alarm 1;
	return 0;
}

#
# Destruktor
#
sub DESTROY {
#	$logger->debug("Node ${\($_[0]->{'name'})} destructor\n");
}


#################################
# Dodawanie/usuwanie aliasów IP
#
sub addIPAlias {
	my ($self, $ip) = @_;
	return unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

	my $ifname = 'honey:' . scalar keys %{$self->{'ip_aliases'}};
	$self->{'ip_aliases'}{$ip} = $ifname;

	system ("ifconfig $ifname $ip") >> 8 == 0
		or return "Couldn't assign $ip to $ifname";

	return 0;
}

sub delIPAlias {
	my ($self, $ip) = @_;
	return unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

	if (!exists $self->{'ip_aliases'}{$ip}) {
		my $msg = "$ip was not assigned by honeypot";
		$logger->warn($msg);
		return $msg;
	}

	my $ifname = $self->{'ip_aliases'}{$ip};
	$logger->info("Removing interface $ifname");

	system("ifconfig $ifname down") >> 8 == 0
		or return "Couldn't disable $ifname interface";

	delete $self->{'ip_aliases'}{$ip};

	return 0;
}

sub getIPAlias {
	my ($self, $ip) = @_;

	return %{$self->{'ip_aliases'}} unless defined $ip;
	return $self->{'ip_aliases'}{$ip};
}



######################################
# Zmiana charakterystyki stosu TCP/IP
#
sub setFingerprint {
	my ($self, $addr, $os) = @_;
	$logger->info("Setting $os fingerprint on $addr");

	my $fpr_file = FINGERPRINTS_DIR . "/$os.conf";

	if (! -f $fpr_file or ! -r $fpr_file) {
		my $msg = "No suck file for $os stack fingerprint";
		$logger->error($msg);
		return $msg;
	}

	$self->{'fingerprints'}{$addr} = $os;
	return $self->_updateIpTables();
}

sub delFingerprint {
	my ($self, $addr) = @_;

	if ($addr) {
		$logger->info("Disabling fingerprint mangling on $addr");
		delete $self->{'fingerprints'}{$addr};
	}
	else {
		$logger->info("Disabling fingerprint mangling");
		$self->{'fingerprints'} = {};
	}

	return $self->_updateIpTables();
}

sub getAvailableFingerprints {
	my ($self) = @_;

	if (!opendir(DIR, FINGERPRINTS_DIR)) {
		my $err = "Couldn't open " . FINGERPRINTS_DIR;
		$logger->error($err);
		return $err;
	}

	my @result;

	foreach (readdir(DIR)) {
		next unless /.+\.conf$/;
		my $os = $_;
		$os =~ s/\.conf$//;
		push(@result, $os);
	}
	closedir(DIR);

	return @result;
}


##########################
# Falszowanie adresow MAC
#
sub setMAC {
	my ($self, $addr, $mac) = @_;
	$logger->info("Setting $mac address on $addr");

	$self->{'spoofed_mac'}{$addr} = $mac;
	$self->_updateArpTables();
}

sub delMAC {
	my ($self, $addr) = @_;
	$logger->info("Disabling MAC mangling on $addr");

	delete $self->{'spoofed_mac'}{$addr};
	return $self->_updateArpTables();
}

sub getMAC {
	my ($self, $ip) = @_;

	return $self->{'spoofed_mac'}{$ip} if defined $ip;
	return %{$self->{'spoofed_mac'}};
}

# usuwa wszystkie odwzorowania adres -> mac
sub cleanMAC {
	my ($self) = @_;
	
	$self->{'spoofed_mac'} = {};
	return $self->_updateArpTables();
}




########################################
# Nasluchiwanie ruchu sieciowego (PCAP)
#
sub addFilter {
	my ($self, $new_filter) = @_;
	$logger->debug("Adding filter: $new_filter");

	push @{$self->{'pcap_filters'}}, $new_filter;
	$self->_compileFilter();
}

sub replaceFilters {
	my ($self, $new_filter) = @_;
	
	$self->{'pcap_filters'} = [$new_filter];
	$self->_compileFilter();
}

sub delFilter {
	my ($self, $number) = @_;

	if ($number) {
		my @filters = @{$self->{'pcap_filters'}};
		@filters = @filters[0..$number-1, $number+1..$#filters];
		$self->{'pcap_filters'} = \@filters;
	}
	else {
		$self->{'pcap_filters'} = [];
	}

	return 0;
}

sub getFilters {
	my ($self) = @_;
	return @{$self->{'pcap_filters'}};
}

sub getFilter {
	my ($self, $number) = @_;
	return @{$self->{'pcap_filters'}} unless defined $number;
	return $self->{'pcap_filters'}[$number];
}

sub disablePcap {
	my ($self) = @_;
	return unless $self->{'pcap'};

	my $fd = Net::Pcap::fileno($self->{'pcap'});
	$self->_removefh($fd);

	Net::Pcap::close($self->{'pcap'});
	$self->{'pcap'} = undef;

	return 0;
}

sub enablePcap {
	my ($self) = @_;

	if (!$self->{'abilities'}{'pcap'}) {
		my $err = "Pcap not supported";
		$logger->error($err);
		return $err;
	}

	if ($self->{'pcap'}) {
		my $err = "Pcap already enabled";
		$logger->info($err);
		return $err;
	}

	$self->_setupPcap();

	my $fd = Net::Pcap::fileno($self->{'pcap'});
	$self->_addfh($fd, 'r');
	$self->{'r_handlers'}{$fd} = sub {
		$logger->debug("Got packet");
		Net::Pcap::loop($self->{'pcap'}, 1, \&_pcapPacket, 'aaa');
	};

	return 0;
}



############################################################
# Pasywne rozpoznawanie zdalnego systemu operacyjnego (p0f)
#
sub enableP0f {
	my ($self) = @_;
	$logger->info('Enabling p0f...');

	my ($rdfh, $wrfh);
	eval {
		my $args = '';
		$args .= '-F ' if $self->{'p0f_opts'}{'fuzzy'};
		$args .= '-p ' if $self->{'p0f_opts'}{'promiscuous'};
		$args .= '-M ' if $self->{'p0f_opts'}{'masq_detection'};
		my $mode = $self->{'p0f_opts'}{'mode'};
		$args .= '-A ' if $mode == 1;
		$args .= '-R ' if $mode == 2;

		my $pid = open2($rdfh, $wrfh, "exec p0f -q -l $args 2>&1");
		$self->{'p0f_pid'} = $pid;
		$self->{'p0f_fh'} = $rdfh;
		$self->_addfh($rdfh, 'r');
		$self->{'r_handlers'}{$rdfh} = sub {
			$logger->info("OS recognized: " . <$rdfh>);
		};
	};
	for ($@) {
		if (/^open2:/) {
			my $msg = 'Couldn\'t start p0f';
			$logger->error($msg);
			return $msg;
		}
	}
}

sub disableP0f {
	my ($self) = @_;
	$logger->info('Disabling p0f...');

	if (defined $self->{'p0f_fh'}) {
		$self->_removefh($self->{'p0f_fh'});
		$self->{'p0f_fh'} = undef;
	}

	CORE::kill 9, $self->{'p0f_pid'}
		if defined $self->{'p0f_pid'};
}

sub setP0fOption {
	my ($self, %opts) = @_;

	$self->{'p0f_opts'}{$_} = $opts{$_}
		foreach (keys %opts);

	if ($self->{'p0f_fh'}) {
		$self->disableP0f();
		$self->enableP0f();
	}

	return 0;
}


#####################################
# Przypisanie us³ugi na danym porcie
#
sub addService {
	my ($self, $addr, $proto, $port, $script, @args) = @_;
	$logger->info("Adding service on $addr:$port ($proto)");

	my $socket = new IO::Socket::INET(
		LocalAddr => $addr,
		LocalPort => $port,
		Proto => $proto,
		Listen => 5,
		Reuse => 1
	);
	if (!$socket) {
		my $msg = "Couldn't open socket: $!";
		$logger->error($msg);
		return $msg;
	}

	$self->{'ports'}{"$addr/$proto/$port"}{'socket'} = $socket;
	$self->{'ports'}{"$addr/$proto/$port"}{'script'} = $script;
	$self->{'ports'}{"$addr/$proto/$port"}{'args'} = join(' ', @args);

	$self->_addfh($socket, 'r');
	$self->{'r_handlers'}{$socket} = sub {
		my $client = $socket->accept();
		if (! $client) {
			$logger->error("Couldn't accept connection ($!)");
			return 1;
		}
		$logger->info("Connection to service $script from " . $client->peerhost);
		if ($self->{'processes_spawned'} >= $self->{'processes_limit'}) {
			$logger->error("Maximum processes already running. Dropping connection");
			close $client;
			return 1;
		}

		my $pid = fork();
		if (! $pid) {
			setsid();
			POSIX::close(3);
			POSIX::dup(1);
			open(STDIN, "<&=".fileno($client));
			open(STDOUT, ">&=".fileno($client));
			{ exec($script, @args); }
			$logger->error("Couldn't run script ($!)");
			exit 1;
		}
		$self->{'processes_spawned'}++;
	};

	return 0;
}

sub delService {
	my ($self, $addr, $proto, $port) = @_;
	if (! exists $self->{'ports'}{"$addr/$proto/$port"}) {
		my $msg = "No service is bound there";
		$logger->warn($msg);
		return $msg;
	}

	$logger->info("Removing service from $addr:$port ($proto)");
	my $fh = $self->{'ports'}{"$addr/$proto/$port"}{'socket'};
	$self->_removefh($fh);
	$fh->close();
	delete $self->{'ports'}{"$addr/$proto/$port"};
	return 0;
}

sub getService {
	my ($self, $addr, $proto, $port) = @_;

	if (defined $port) {
		if (defined $self->{'ports'}{"$addr/$proto/$port"}) {
			my $result;
			$result = $self->{'ports'}{"$addr/$proto/$port"}{'script'};
			$result .= ' ' . $self->{'ports'}{"$addr/$proto/$port"}{'args'}
				if defined ($self->{'ports'}{"$addr/$proto/$port"}{'args'});
			return $result;
		}
		return 0;
	}

	my %result;
	foreach (keys %{$self->{'ports'}}) {
		my $value;
		$value = $self->{'ports'}{$_}{'script'};
		$value .= ' ' . $self->{'ports'}{$_}{'args'}
			if defined ($self->{'ports'}{$_}{'args'});
		$result{$_} = $value;
	}
	return %result;
}

#
# Ustawia ile maksymalnie moze dzialaæ jednocze¶nie 
# modulow z imitacjami uslug
#
sub setServicesLimit {
	my ($self, $limit) = @_;
	return unless defined $limit;

	$self->{'processes_limit'} = $limit;
}

sub getServicesLimit {
	my ($self) = @_;
	return $self->{'processes_limit'};
}


######################################################
# G³ówna pêtla serwera (obs³uga zdarzeñ na gniazdach)
#

sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});

	local $| = 1;
	$SIG{'PIPE'} = sub {
		$logger->warn('Broken pipe');
	};
	$SIG{'CHLD'} = sub {
		$self->{'processes_spawned'}--
			if $self->{'processes_spawned'} > 0;
		my $msg = "Subprocess finished ";
		$msg .= "(running: ".$self->{'processes_spawned'}."/".$self->{'processes_limit'}.").";
		$logger->info($msg);
	};

	if ($self->{'mode'} eq 'sensor') {
		if (! $self->{'connected'}) {
			$logger->debug("Trying to (re)connect to my master");
			$self->_connect_to_master();
		}
	}

	$logger->debug("Entering main loop - node " . $self->{'name'});
	for (;;) {
		$logger->debug("Waiting on select(2) syscall...");

		$logger->debug("Write watched handles: " , $self->{'w_set'}->handles);
		my ($r_ready, $w_ready, $e_ready) =
			IO::Select->select(
				$self->{'r_set'}, $self->{'w_set'}, $self->{'e_set'},
				$self->{'stimeout'});

		if (!defined($r_ready)) {
			#
			# Na zadnym uchwycie nie bylo zdarzenia
			#
			$logger->debug("Timeout");
			if ($self->{'mode'} eq 'sensor') {
				if (! $self->{'connected'}) {
					$logger->debug("Trying to (re)connect to my master");
					$self->_connect_to_master();
				}
			}
			next;
		}

		foreach my $fh (@$r_ready) {
			$logger->debug("Something ($fh) in read ready set");

			$self->{'r_handlers'}{$fh}()
				if exists($self->{'r_handlers'}{$fh});
		}
		foreach my $fh (@$w_ready) {
			$logger->debug("Something ($fh) in write ready set");

			$self->{'w_handlers'}{$fh}()
				if exists($self->{'w_handlers'}{$fh});
		}
	}
}


#
# Wykonuje funkcjê przes³an± przez sieæ wraz z argumentami
# i jej kontekstem wywo³ania
#
sub process_command {
	my ($self, $sock) = @_;

	my $peek = $sock->peek(undef, 1);
	if (!defined $peek) {
		$logger->error("peek() : $!");
		return;
	}
	if ($peek == 0) {
		Log::Log4perl->eradicate_appender('MasterAppender');
		$self->{'appender'} = undef;
		$logger->debug("My master closed connection.");
		$self->_removefh($sock, 're');
		$self->{'connected'} = 0;
		close($sock);
	}
	else {
		$logger->debug("Processing data from server.");

		my $buf;
		sysread($sock, $buf, 4);
		my $len = unpack('N', $buf);
		sysread($sock, $buf, $len);
		my ($function, $arrayctx, @args);
		eval {
			($function, $arrayctx, @args) = @{thaw($buf)};
		};
		for ($@) {
			if (/Magic number checking on storable string failed/) {
				$logger->error("Wrong data received from client.");
				return;
			}
		}

		local $" = ',';
		$logger->debug("Running $function(@args) in "
			. ($arrayctx?'list':'scalar') . ' context');

		# XXX
		$self->_callFunction($function, $arrayctx, @args);
		return 0;
	}
}


#
# Wykonuje funkcjê na podanym wê¼le sieci
#
sub runOnNode {
	my ($self, $name, $function, @args) = @_;
	my @result;

	if ($name eq $self->{'name'}) {
		no strict 'refs';
		$self->_callFunction($function, wantarray, @args);
		return undef;
	}

	return "No such node: $name"
		unless exists($self->{'sensors'}{$name});

	#
	# Odbedzie sie wywolanie zdalne
	#

	my $sensor = $self->{'sensors'}{$name};
	my $sensor_sock = $sensor->{'socket'};

	$self->{'w_handlers'}{$sensor_sock} = sub {
		$sensor->doOnReturn(sub {
				my ($self, @ret) = @_;
				my $node = $self->{'master'};
				$self->doOnReturn(undef);
				$logger->info(@ret);
				$node->{'w_handlers'}{$node->{'master_sock'}} = sub {
					Commons::sendDataToSocket(
						$node->{'master_sock'}, 'ret', @ret);
					$node->_removefh($node->{'master_sock'}, 'w');
				};
				$node->_addfh($node->{'master_sock'}, 'w');
			});
		$sensor->call($function, wantarray, @args);
	};
	$self->_addfh($sensor->{'socket'}, 'w');

	return undef;
}


1;

# vim: set ts=3 sw=3 ft=perl:

