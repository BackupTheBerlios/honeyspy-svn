#!/usr/bin/perl

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use Storable qw(nstore_fd freeze);
use IO::Socket::SSL; # qw(debug4);
use IO::Socket::INET;
use Storable ('thaw');
use POSIX qw(setsid);
use Carp;
use Master;

require Exporter;
our @ISA = qw(Exporter);
# (nie wolno eksportowac metod)

my $logger = get_logger();

our $CORRECT_CERT;
*CORRECT_CERT =
	\"/C=PL/O=HoneySpy network/OU=Master Server/CN=Master";


#
# Wezel powinien miec atrybuty
# 	nazwa
# 	tryb [master lub sensor]
# 	deskryptor gniazda
# 	lista umiejetnosci
# 	lista interfejsow
# 	lista portow
# 	lista uchwytów plików: gotowych do odczytu, zapisu, wyj±tku
#

sub new($) {
	$logger->debug("konstruktor Node\n");

	my $class = ref($_[0]) || $_[0];
	my $self = {
		'name' => $_[1],
		'socket' => \*STDOUT,
		'mode' => 'sensor',

		'abilites' => {},
		'interfaces' => [],
		'ports' => [],

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
	return bless $self, $class;
}


#
# XXX
# Akcesory i modifykatory powinny byæ robione automatycznie
# [automatyczna modifikacja wpisów w przestrzeni nazw modu³u]
#
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


sub DESTROY {
#	$logger->debug("Node ${\($_[0]->{'name'})} destructor\n");
}

sub kill {
	$logger->info('Node is going down in a moment');
	$SIG{'ALRM'} = sub {
		exit 0;
	};
	alarm 1;
	return 0;
}

sub setFingerprint {
	my ($addr, $os) = @_;
	$logger->info("Setting $os fingerprint on $addr");
}

sub delFingerprint {
	my ($addr) = @_;
	$logger->info("Disabling fingerprint mangling on $addr");
}

sub setMAC {
	my ($addr, $mac) = @_;
	$logger->info("Setting $mac address on $addr");
}

sub delMAC {
	my ($addr) = @_;
	$logger->info("Disabling MAC mangling on $addr");
}


#
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

	$self->addfh($socket, 'r');
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


# XXX
sub sendToPeer {
	my ($sock, $serialized) = (shift, freeze [@_]);
	print $sock pack('N', length($serialized));
	print $sock $serialized;
}


sub _configure_master {
   my ($self, $master) = @_;
	
	$self->addfh($master, 're');
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
	$master = IO::Socket::SSL->new( PeerAddr => '127.0.0.1',
		PeerPort => '9000',
		Proto    => 'tcp',
		SSL_use_cert => 1,

		SSL_key_file => "../certs/".$self->{'name'}."-key.pem",
		SSL_cert_file => "../certs/".$self->{'name'}."-cert.pem",
		SSL_ca_file => '../certs/master-cert.pem',

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

		if ($subject_name eq $CORRECT_CERT
			&& $issuer_name eq $CORRECT_CERT) {
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


sub removefh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->remove($fh);
		delete $self->{$_.'_handlers'}{$fh};
	}
}


sub addfh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->add($fh);
	}
}


sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});

	if ($self->{'mode'} eq 'sensor') {
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


sub process_command {
	my ($self, $sock) = @_;
	$logger->debug("Processing data from server.");

	if ($sock->peek(undef, 1) == 0) {
		$logger->debug("My master closed connection.");
		$self->removefh($sock, 're');
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

		$self->addfh($sock, 'w');
		$self->{'w_handlers'}{$sock} = sub {
			sendToPeer($sock, @result);
			$self->removefh($sock, 'w');
		};

	}
}


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

