#!/usr/bin/perl
use strict;
use warnings;
use File::Path qw(make_path);

# Forced command for the CertMgr automation SSH key — see the
# `command="..."` restriction on this key's line in root's
# authorized_keys on lets-encrypt01. sshd runs THIS script for every
# connection using that key, regardless of what the client asked to run;
# the client's actual request arrives only via $ENV{SSH_ORIGINAL_COMMAND},
# which is NEVER executed directly here. Only the two exact shapes
# certbot's authenticator.pl/cleanup.pl send are recognized; anything else
# is rejected and logged. This converts a nominally-root key into
# something that can only ever place or remove one ACME challenge file.
#
# See docs/administration.md#ssh-credentials-for-hook-scripts and
# deploy/test-certmgr-challenge-helper.sh for the accompanying test
# harness (CERTMGR_HELPER_WEBROOT/CERTMGR_HELPER_OWNER let that harness
# run this against a scratch directory instead of production paths).

my $WEBROOT        = $ENV{CERTMGR_HELPER_WEBROOT} // '/var/www/html';
my $CHALLENGE_DIR  = "$WEBROOT/.well-known/acme-challenge";
my $OWNER          = $ENV{CERTMGR_HELPER_OWNER}   // 'secauto';

# ACME tokens / key-authorizations are base64url: [A-Za-z0-9_-]. Real
# tokens observed in practice run ~43 chars; bounds are generous but
# strictly exclude '/', '.', and shell metacharacters (no path traversal,
# no injection).
my $TOKEN_RE = qr/[A-Za-z0-9_-]{20,64}/;

my $cmd = $ENV{SSH_ORIGINAL_COMMAND} // '';

sub reject {
    my ($reason) = @_;
    system('logger', '-t', 'certmgr-challenge-helper',
           "REJECTED from=" . ($ENV{SSH_CLIENT} // 'unknown') . " reason=\"$reason\" cmd=\"$cmd\"");
    print STDERR "certmgr-challenge-helper: rejected ($reason)\n";
    exit 1;
}

# ── Shape 1: place the challenge file (authenticator.pl) ────────────────────
if ($cmd =~ m{^cd \Q$WEBROOT\E; echo (${TOKEN_RE}\.${TOKEN_RE}) > \.well-known/acme-challenge/(${TOKEN_RE}); chown -R \Q$OWNER\E: \.well-known;$}) {
    my ($validation, $token) = ($1, $2);
    my ($token_prefix) = split(/\./, $validation, 2);
    reject("token/validation mismatch") unless $token_prefix eq $token;

    make_path($CHALLENGE_DIR) unless -d $CHALLENGE_DIR;
    my $path = "$CHALLENGE_DIR/$token";
    open(my $fh, '>', $path) or reject("cannot write $path: $!");
    print $fh $validation;
    close($fh);

    # Best-effort — a chown failure shouldn't fail issuance, since
    # certbot's HTTP check only needs the file readable, not its owner.
    system('chown', '-R', "$OWNER:", "$WEBROOT/.well-known") == 0
        or system('logger', '-t', 'certmgr-challenge-helper', "WARN chown failed for $path");

    system('logger', '-t', 'certmgr-challenge-helper', "WROTE token=$token");
    exit 0;
}

# ── Shape 2: remove the challenge file (cleanup.pl) ─────────────────────────
if ($cmd =~ m{^cd \Q$CHALLENGE_DIR\E; rm -f \./(${TOKEN_RE});$}) {
    my ($token) = $1;
    my $path = "$CHALLENGE_DIR/$token";
    unlink($path) if -e $path;   # cleanup.pl already tolerates a missing file
    system('logger', '-t', 'certmgr-challenge-helper', "REMOVED token=$token");
    exit 0;
}

reject("unrecognized command");
