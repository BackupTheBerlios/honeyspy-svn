#!/usr/bin/perl -w
use strict;
use Switch;

$| = 1;

my $komeda;
my $user="@";
my $nazwa_serwera="server.pl";

print "220 $nazwa_serwera ESMTP Wita\n";

while(1)
{
	$komeda = <STDIN>;
	chop $komeda;

	#musi byc poza switchem bo w casie w znakach {} nie widac juz zmiennej $1
	#czyzby kazdy blok mial wlasna?
	if( $komeda =~ /^MAIL FROM: *(<.*>)$/i) {
			print "554 5.7.1 $1 : Sender address rejected:\n";	
	}

	switch($komeda){	
		case "" { print "500 5.5.2 Error: bad syntax\n";}
		
		case /^HELO$/	{
			print "501 Syntax: HELO hostname\n";
		}
	
		case /^HELO /i    {
			print "250 $nazwa_serwera\n";
		}
		
		case /^EHLO$/  {
			print "501 Syntax: EHLO hostname\n";
		}
		
		case /^EHLO /i {
			print <<EOF
			250-$nazwa_serwera
			250-PIPELINING
			250-SIZE 30000000
			250-VRFY
			250-ETRN
			250-STARTTLS
			250-AUTH PLAIN LOGIN
			250-AUTH=PLAIN LOGIN
			250-ENHANCEDSTATUSCODES
			250-8BITMIME
			250 DSN
EOF
		}
		
	        case /^QUIT$/i {
			print "221 2.0.0 Bye\n";
			exit 0;
		}
		
		case /^MAIL FROM:$/i {
			print "501 5.5.4 Syntax: MAIL FROM:<address>\n";
		}

		else {
			   print "502 5.5.2 Error: command not recognized\n";
		}
	}
}
