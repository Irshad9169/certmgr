#!/usr/bin/perl
use strict;
use warnings;
use HTTP::Tiny;   # core module since Perl 5.13.9 — nothing to install

# CGI script for lets-encrypt01's web server, mounted ONLY at
# /.well-known/acme-challenge/ (Apache: ScriptAliasMatch; nginx: fcgiwrap +
# a location block — see docs/administration.md for both). Replaces the
# earlier SSH-based design where CertMgr pushed challenge files here via a
# root/service SSH key: instead, this script PULLS the current challenge
# content from CertMgr's own automation host and returns it verbatim.
#
# No SSH, no root, no credentials, no filesystem writes on this host at
# all. The only outbound call this makes is to the hardcoded constant
# below — never derived from the request — so there is no way for a
# request to redirect it anywhere else (no open proxy, no SSRF).
#
# See deploy/test-certmgr-challenge-proxy.sh for the accompanying test
# harness (CERTMGR_CHALLENGE_PROXY_UPSTREAM_HOST/_PORT let it point this
# script at a throwaway local server instead of production).

my $UPSTREAM_HOST   = $ENV{CERTMGR_CHALLENGE_PROXY_UPSTREAM_HOST} // 'test05.hyd.int.untd.com';
my $UPSTREAM_PORT   = $ENV{CERTMGR_CHALLENGE_PROXY_UPSTREAM_PORT} // 8080;
my $TIMEOUT_SECONDS = 5;

# Same bounds as deploy/certmgr-challenge-helper.pl's SSH-side validation.
my $TOKEN_RE = qr/^[A-Za-z0-9_-]{20,64}\z/;

sub log_line {
    my ($msg) = @_;
    system('logger', '-t', 'certmgr-challenge-proxy', $msg);
}

sub respond {
    my ($status, $body) = @_;
    print "Status: $status\r\n";
    print "Content-Type: text/plain\r\n";
    print "Content-Length: " . length($body) . "\r\n\r\n";
    print $body;
    exit 0;
}

my $method = $ENV{REQUEST_METHOD} // '';
if ($method ne 'GET') {
    log_line("REJECTED method=\"$method\"");
    respond('405 Method Not Allowed', '');
}

# PATH_INFO is the part of the URL past the script's mount point — mounted
# at /.well-known/acme-challenge/, a request for .../acme-challenge/<token>
# arrives as PATH_INFO=/<token>.
my $path_info = $ENV{PATH_INFO} // '';
$path_info =~ s{^/}{};

unless ($path_info =~ $TOKEN_RE) {
    log_line("REJECTED malformed token=\"$path_info\"");
    respond('400 Bad Request', '');
}
my $token = $path_info;

my $http = HTTP::Tiny->new(timeout => $TIMEOUT_SECONDS);
my $url  = "http://$UPSTREAM_HOST:$UPSTREAM_PORT/.well-known/acme-challenge/$token";
my $res  = $http->get($url);

unless ($res->{success}) {
    log_line("MISS token=$token upstream_status=$res->{status}");
    respond('404 Not Found', '');
}

log_line("SERVED token=$token");
respond('200 OK', $res->{content});
