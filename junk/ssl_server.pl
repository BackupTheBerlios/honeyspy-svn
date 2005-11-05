
use Log::Log4perl qw(:easy);
use strict;

use IO::Socket::SSL;
use Sensor;

use Storable qw(nstore_fd store_fd thaw);


my $logger = get_logger();
Log::Log4perl->easy_init($DEBUG);


my ($sock, $s);
my %sensors;

$IO::Socket::SSL::DEBUG = 1;


if(!($sock = IO::Socket::SSL->new( Listen => 5,
				   LocalAddr => 'localhost',
				   LocalPort => 9000,
				   Proto     => 'tcp',
				   Reuse     => 1,

					SSL_key_file => '../certs/master-key.pem',
					SSL_cert_file => '../certs/master-cert.pem',
					SSL_ca_file => '../certs/master-cert.pem',

				   SSL_verify_mode => 0x01,
				 )) ) {
    $logger->fatal("unable to create socket: ", &IO::Socket::SSL::errstr, "\n");
    exit(0);
}

while (1) {
	$logger->info("waiting for next connection.\n");

	while(($s = $sock->accept())) {
		my ($peer_cert, $subject_name, $issuer_name, $date, $str);

		if( ! $s ) {
			$logger->info("error: ", $sock->errstr, "\n");
			next;
		}

		$logger->info("connection opened ($s).\n");

		if( ref($sock) eq "IO::Socket::SSL") {
			$subject_name = $s->peer_certificate("subject");
			$issuer_name = $s->peer_certificate("issuer");
		}
		if (!$subject_name or !$issuer_name) {
			$logger->fatal("£acz±cy siê sensor nie przedstawi³ certyfikatu.\n");
			close $s;
			next;
		}

		$logger->info("\t subject: '$subject_name'.\n");
		$logger->info("\t issuer: '$issuer_name'.\n");

		my $sensor_name = $subject_name;
		for ($sensor_name) {
			s'.*CN='';
			s'/.*'';
		}
		my $sensor = Sensor->new($sensor_name);

		$sensor->{'socket'} = $s;
		$sensors{$sensor_name} = $sensor;

#		$sensor->blah('a', 'b');
#		scalar $sensor->blah('a', 'b');
#		@{[$sensor->blah('a', 'b')]};

		# odczytanie odpowiedzi
		my $buf;
		sysread($s, $buf, 4);
		my $len = unpack('N', $buf);
		sysread($s, $buf, $len);
		my @resp = @{thaw($buf)};
		$logger->debug("Odpowiedz sensora:\n");
		local $" = "\n->";
		$logger->debug("@resp\n");

		close($s);
		$logger->info("\t connection closed.\n");
	}
}

$sock->close();

