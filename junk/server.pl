#!/usr/bin/perl -w

use strict;
use IO::Socket::SSL;

my $sock;

if(!($sock = IO::Socket::SSL->new( Listen => 5,
                                   LocalAddr => 'localhost',
                                   LocalPort => 9000,
                                   Proto     => 'tcp',
                                   Reuse     => 1,
                                   SSL_verify_mode => 0x01,
                                   SSL_passwd_cb => sub {return "bluebell"},
                                 )) ) {
    warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
    exit(0);
}   
warn "socket created: $sock.\n";



