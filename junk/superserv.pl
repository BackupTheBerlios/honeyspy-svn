#!/usr/bin/perl -w

use strict;
use IO::Socket::INET;

my $socket = new IO::Socket::INET(
	LocalAddr => '127.0.0.1',
	LocalPort => '5000',
	Proto => 'tcp',
	Listen => 5,
	Reuse => 1
);

my $client = $socket->accept();

my $pid = fork();

if (! $pid) {
	open(STDIN, "<&=".fileno($client));
	open(STDOUT, ">&=".fileno($client));
	open(STDERR, ">&=".fileno($client));
	exec ('/bin/cat', '/etc/passwd') or die "$!";
}
else {
	print "koniec";
}

