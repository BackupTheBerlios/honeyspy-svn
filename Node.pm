#!/usr/bin/perl -T

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use Storable qw(nstore_fd freeze);
use IO::Socket::SSL; # qw(debug4);
use IO::Socket::INET;
use NetPacket::IP;
use NetPacket::Ethernet qw(:strip);
use NetPacket::Ethernet;
use Net::Pcap;
use Storable ('thaw');
use POSIX qw(setsid);
use Carp;
use Master;

require Exporter;
our @ISA = qw(Exporter);

my $logger = get_logger();

use constant CORRECT_CERT =>
	"/C=PL/O=HoneySpy network/OU=Master Server/CN=Master";


#
# sendDataToSocket - Metoda statyczna, wysy³a dane na $sock
#
sub sendDataToSocket {
	my ($sock, $serialized) = (shift, freeze [@_]);
	print $sock pack('N', length($serialized));
	print $sock $serialized;
}


#
# Konstruktor
#
sub new {
	my ($class,  $config_file) = 
		(ref($_[0]) || $_[0], $_[1]);

	$logger->debug("konstruktor Node\n");

	my $self = {
		'name' => 'unnamed',
		'socket' => \*STDOUT,
		'mode' => 'sensor',

		# Atrybuty dzialania serwera
		'abilities' => {
			'p0f' => undef,         # rozpoznawanie zdalnego os
			'fingerprint' => undef, # falszowanie stosu
			'mac' => undef,         # falszowanie adresow mac
			'pcap' => undef,        # nasluchiwanie pakietow
		},
		'interfaces' => [],
		'ports' => [],

		# Interfejs nasluchiwania (PCAP)
		'pcap' => undef,
		'pcap_filters' => [],
		'compiled_filter' => undef,

		# przypisane przez honeypota ip aliasy (ip -> interfejs)
		'ip_aliases' => {},

		# spoofowane adresy mac (ip -> mac)
		'spoofed_mac' => {},

		# Handlery dla zdarzen na uchwytach plikow
		'r_handlers' => {},
		'w_handlers' => {},
		'e_handlers' => {},

		# Zbiory uchwytow plikow, ktore trzeba obserwowac
		'r_set' => new IO::Select(),
		'w_set' => new IO::Select(),
		'e_set' => new IO::Select(),

      'stimeout' => 5,
      'reconnect' => 4, # tyle sekund miedzy reconnect
      'connected' => 0
	};

	bless $self, $class;

	$self->readConfig($config_file)
		if defined $config_file;

	$self->_checkAbilities();

	$self->_initIPAliases()
		if $self->{'abilities'}{'ipaliases'};
	$self->_setupPcap()
		if $self->{'abilities'}{'pcap'};

	return $self;
}


################################################################################
# Metody prywatne
################################################################################

#
# XXX Do polepszenia (jest wstepna prosta wersja)
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
	eval {
		require Net::P0f;
	};
	$self->{'abilities'}{'p0f'} = 1 if ! $@;

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

	system('ebtables -t nat -F PREROUTING ; arptables -t mangle -F OUTPUT') >> 8 == 0
		or return "Couldn't clean ebtables and arptables rules";

	my $n = 0;
	while ((my ($ip, $mac) = each(%{$self->{'spoofed_mac'}}))) {

		next unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;
		next unless $mac =~ /([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}/;

		system("arptables -t mangle -A OUTPUT --h-length 6 -o honey "
		. "-s $ip -j mangle --mangle-mac-s $mac") >> 8 == 0
			or return "Couldn't set arptables rule ($ip -> $mac)";

		system("ebtables -t nat -A PREROUTING -d $mac -j redirect") >> 8 == 0
			or return "Couldn't set ebtables rule (to redirect $mac)";

		$n++;
	}

	return 0;
}

sub _compileFilter {
	my ($self) = @_;
	my $compiled;

	return unless @{$self->{'pcap_filters'}};

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
	$msg .= ' proto:' . $ip_obj->{'proto'};
	$msg .= ' flags:' . $ip_obj->{'flags'};
	$logger->info($msg);
}

sub _callFunction {
	my ($self, $function, $arrayctx, @args) = @_;
	my @result;

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
	return @result;
}

sub _configure_master {
   my ($self, $master) = @_;
	
	$self->_addfh($master, 're');
	$self->{'r_handlers'}{$master} = sub {
		$self->process_command($master);
	};

	$self->{'connected'} = 1;
	$self->{'master_sock'} = $master;
}


sub _connect_to_master {
   my ($self) = @_;
	my $master;

	$logger->debug("Connecting to 127.0.0.1:9000...");
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
	if( ref($master) eq "IO::Socket::SSL") {
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

	$self->_configure_master($master);
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
# U¿ywane tylko do testów RPC
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
	$logger->debug("Jestem wezel ${\($_[0]->{name})}\n");
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
}

sub delFingerprint {
	my ($self, $addr) = @_;
	$logger->info("Disabling fingerprint mangling on $addr");
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
	$self->{'r_set'}->remove($fd);
	delete $self->{'r_handlers'}{$fd};
}

sub enablePcap {
	my ($self) = @_;

	if (!$self->{'pcap'}) {
		my $err = "Pcap not supported";
		$logger->error($err);
		return $err;
	}
	
	
	my $fd = Net::Pcap::fileno($self->{'pcap'});
	$self->{'r_set'}->add($fd);
	$self->{'r_handlers'}{$fd} = sub {
		$logger->debug("Got packet");
		Net::Pcap::loop($self->{'pcap'}, 1, \&_pcapPacket, 'aaa');
	};

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

	$self->_addfh($socket, 'r');
	$self->{'r_handlers'}{$socket} = sub {
		my $client = $socket->accept();
		if (! $client) {
			$logger->error("Couldn't accept connection ($!)");
			return 1;
		}
		$logger->debug("Connection to service $script from " . $client->peerhost);
		$SIG{'CHLD'} = 'IGNORE';
		my $pid = fork();
		if (! $pid) {
			setsid();
			open(STDIN, "<&=".fileno($client));
			open(STDOUT, ">&=".fileno($client));
#			open(STDERR, ">&=".fileno($client));
			{ exec($script, @args); }
			$logger->error("Couldn't run script ($!)");
			return 1;
		}
	};

	return 0;
}

sub delService {
	my ($self, $addr, $proto, $port) = @_;
	$logger->info("Removing service from $addr:$port ($proto)");
}





######################################################
# G³ówna pêtla serwera (obs³uga zdarzeñ na gniazdach)
#

sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});


	# XXX
	# Brak mozliwosc polaczenia nie powinien tu chyba blokowac pracy wezla
	if ($self->{'mode'} eq 'sensor') {
		$SIG{INT} = sub {
			$logger->info("Caught SIGINT, dying.");
			exit(0);
		};
		while (!($self->_connect_to_master())) {
			my $delay = $self->{'reconnect'};
			$logger->info("Retrying in $delay seconds");
			select(undef, undef, undef, $delay);
		}
	}

	local $| = 1;

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
					$logger->debug("Trying to reconnect to my master");
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
	$logger->debug("Processing data from server.");

	if ($sock->peek(undef, 1) == 0) {
		$logger->debug("My master closed connection.");
		$self->_removefh($sock, 're');
		$self->{'connected'} = 0;
		close($sock);
	}
	else {
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

		my @result = $self->_callFunction($function, $arrayctx, @args);
		$logger->debug("Function result: @result");

		$self->_addfh($sock, 'w');
		$self->{'w_handlers'}{$sock} = sub {
			sendDataToSocket($sock, @result);
			$self->_removefh($sock, 'w');
		};

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
		return $self->_callFunction($function, wantarray, @args);
	}

	return "No such node: $name"
		unless exists($self->{'sensors'}{$name});

#	my $socket = $self->{'sensors'}{$name}{'socket'};
	my $sensor = $self->{'sensors'}{$name};
	$sensor->sendToPeer($function, wantarray, @args);

	# XXX tu by sie przydalo poprawic asynchronicznosc
	return $sensor->recvFromPeer();
}


1;

