
use strict;
use IO::Socket::SSL;

use Sensor;
use Storable ('thaw', 'freeze');

my ($sock, $buf);

#$IO::Socket::SSL::DEBUG = 4;

if(!($sock = IO::Socket::SSL->new( PeerAddr => 'localhost',
				   PeerPort => '9000',
				   Proto    => 'tcp',
				   SSL_use_cert => 1,

					SSL_key_file => '../certs/sensor1-key.pem',
					SSL_cert_file => '../certs/sensor1-cert.pem',
					SSL_ca_file => '../certs/master-cert.pem',

				   SSL_verify_mode => 0x01,
				 ))) {
    warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
    exit(0);
} else {
    warn "connect ($sock).\n" if ($IO::Socket::SSL::DEBUG);
}

# check server cert.
my ($subject_name, $issuer_name, $cipher);
if( ref($sock) eq "IO::Socket::SSL") {
    $subject_name = $sock->peer_certificate("subject");
    $issuer_name = $sock->peer_certificate("issuer");
    $cipher = $sock->get_cipher();
}
warn "cipher: $cipher.\n", "server cert:\n", 
    "\t '$subject_name' \n\t '$issuer_name'.\n\n";

#my ($buf) = $sock->getlines;

{
	sysread($sock, $buf, 4);
	my $len = unpack('N', $buf);
	sysread($sock, $buf, $len);
	my ($function, $arrayctx, @args) = @{thaw($buf)};

	local $" = ',';
	print "Klient powinien wywo�a� $function(@args) w kontekscie "
		. ($arrayctx?'listowym':'skalarnym') . "\n";

	
	no strict 'refs';
	$function =~ s/.*:://;

	$SIG{PIPE} = sub {print "x\n"};

	my $serialized;
	if (defined $arrayctx) {
		if ($arrayctx) {
			my @array_result = @{[&{*{$function}}]};
			$serialized = freeze [@array_result];
			sendToPeer($sock, @array_result);
		}
		else {
			my $scalar_result = scalar &{*{$function}};
			$serialized = freeze [$scalar_result];
			sendToPeer($sock, $scalar_result);
		}
	}
	else { # void context
		&{*{$function}};
	}

}

#$|=1;
#while (defined($buf = <$sock>)) {
#	print "$buf";
#}


$sock->close();

print "read: '$buf'.\n";

sub blah() {
	print "Funkcja blah ";
	if (!defined wantarray) {
		print "Kontekst void\n";
	}
	elsif (wantarray) {
		return ('el1', 'el2', 'fjaksdjfs');
	}
	else {
		return 'asdfasfd';
	}
}

