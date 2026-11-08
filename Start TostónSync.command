#!/bin/sh
exec /usr/bin/perl -x "$0" "$@"
#!perl
use strict;
use warnings;
use utf8;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use IO::Select;
use Socket qw(AF_INET SOCK_STREAM SOL_SOCKET SO_ERROR sockaddr_in inet_aton);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK O_RDONLY O_NOFOLLOW S_ISREG);
use Errno qw(EINPROGRESS EWOULDBLOCK EAGAIN EINTR ECONNREFUSED);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC sleep);
use Cwd qw(abs_path);
use File::Basename qw(dirname);

# Direct sockets: no proxy, DNS, shell interpolation, loader probe or retry.
sub clock_now { return clock_gettime(CLOCK_MONOTONIC); }
sub wait_socket {
    my ($socket, $write, $deadline) = @_;
    my $left = $deadline - clock_now();
    return 0 unless $left > 0;
    my $selector = IO::Select->new($socket);
    my @ready = $write ? $selector->can_write($left) : $selector->can_read($left);
    return @ready && clock_now() < $deadline;
}
sub connect_once {
    my ($ip, $port, $deadline) = @_;
    return (undef, 'unknown') unless clock_now() < $deadline;
    socket(my $socket, AF_INET, SOCK_STREAM, 0) or return (undef, 'unknown');
    my $flags = fcntl($socket, F_GETFL, 0);
    # Apple's bundled Perl Socket omits Darwin's SO_NOSIGPIPE constant.
    unless ($^O eq 'darwin' && defined($flags) &&
            fcntl($socket, F_SETFL, $flags | O_NONBLOCK) &&
            setsockopt($socket, SOL_SOCKET, 0x1022, pack('i', 1))) {
        close($socket); return (undef, 'unknown');
    }
    if (!connect($socket, sockaddr_in($port, inet_aton($ip)))) {
        my $error = 0 + $!;
        if ($error == EINPROGRESS || $error == EWOULDBLOCK) {
            unless (wait_socket($socket, 1, $deadline)) {
                close($socket); return (undef, 'unknown');
            }
            my $result = getsockopt($socket, SOL_SOCKET, SO_ERROR);
            unless (defined($result) && length($result) == length(pack('i', 0))) {
                close($socket); return (undef, 'unknown');
            }
            $error = unpack('i', $result);
        }
        if ($error) {
            close($socket);
            return (undef, $error == ECONNREFUSED ? 'refused' : 'unknown');
        }
    }
    return ($socket, 'connected');
}
sub send_bytes {
    my ($socket, $bytes, $deadline) = @_;
    my $offset = 0;
    while ($offset < length($bytes)) {
        return 0 unless wait_socket($socket, 1, $deadline);
        my $sent = syswrite($socket, $bytes, length($bytes) - $offset, $offset);
        if (!defined($sent)) {
            next if $! == EINTR || $! == EAGAIN || $! == EWOULDBLOCK;
            return 0;
        }
        return 0 unless $sent > 0;
        $offset += $sent;
    }
    return clock_now() < $deadline;
}

# JSON::PP validates strings/UTF-8. Track keys before constructing objects so a
# repeated (including escaped) identity key cannot silently replace another one.
sub json_value {
    my ($text, $depth) = @_;
    die "JSON depth" if $depth > 32;
    $$text =~ /\G[ \t\r\n]*/gc;
    if ($$text =~ /\G("(?:[^"\\\x00-\x1f]|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*")/gc) {
        return JSON::PP->new->utf8->allow_nonref->decode($1);
    }
    if ($$text =~ /\G\{/gc) {
        my %value;
        $$text =~ /\G[ \t\r\n]*/gc;
        return \%value if $$text =~ /\G\}/gc;
        while (1) {
            $$text =~ /\G[ \t\r\n]*/gc;
            die "JSON key" unless substr($$text, pos($$text), 1) eq '"';
            my $key = json_value($text, $depth + 1);
            die "duplicate JSON key" if exists($value{$key});
            die "JSON colon" unless $$text =~ /\G[ \t\r\n]*:/gc;
            $value{$key} = json_value($text, $depth + 1);
            $$text =~ /\G[ \t\r\n]*/gc;
            last if $$text =~ /\G\}/gc;
            die "JSON comma" unless $$text =~ /\G,/gc;
        }
        return \%value;
    }
    if ($$text =~ /\G\[/gc) {
        my @value;
        $$text =~ /\G[ \t\r\n]*/gc;
        return \@value if $$text =~ /\G\]/gc;
        while (1) {
            push @value, json_value($text, $depth + 1);
            $$text =~ /\G[ \t\r\n]*/gc;
            last if $$text =~ /\G\]/gc;
            die "JSON comma" unless $$text =~ /\G,/gc;
        }
        return \@value;
    }
    if ($$text =~ /\G(true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/gc) {
        return JSON::PP->new->allow_nonref->decode($1);
    }
    die "JSON value";
}
sub status_version {
    my ($body) = @_;
    my $value = eval {
        pos($body) = 0;
        my $parsed = json_value(\$body, 0);
        $body =~ /\G[ \t\r\n]*/gc;
        die "JSON trailing bytes" unless pos($body) == length($body);
        $parsed;
    };
    return undef if $@ || ref($value) ne 'HASH' || ref($value->{app}) ||
        !defined($value->{app}) || $value->{app} ne 'TostónSync' ||
        ref($value->{version}) || !defined($value->{version}) ||
        $value->{version} !~ /\A(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\z/;
    return $value->{version};
}
sub read_status {
    my ($socket, $deadline) = @_;
    my $response = '';
    my ($header_bytes, $body_bytes);
    while (length($response) <= 65536) {
        return undef unless wait_socket($socket, 0, $deadline);
        my $read = sysread($socket, my $part, 4096);
        if (!defined($read)) {
            next if $! == EINTR || $! == EAGAIN || $! == EWOULDBLOCK;
            return undef;
        }
        return undef unless $read > 0;
        $response .= $part;
        return undef if length($response) > 65536 || index($response, "\0") >= 0;
        if (!defined($header_bytes)) {
            my $end = index($response, "\r\n\r\n");
            if ($end < 0) { return undef if length($response) > 8192; next; }
            return undef if $end > 8192;
            my @lines = split /\r\n/, substr($response, 0, $end);
            return undef unless shift(@lines) =~ /\AHTTP\/1\.[01] 200 [^\r\n]*\z/;
            my %headers;
            for my $line (@lines) {
                return undef unless $line =~ /\A([A-Za-z0-9-]+):[ \t]*([^\r\n]*)\z/;
                my ($key, $value) = (lc($1), $2);
                return undef if exists($headers{$key});
                $headers{$key} = $value;
            }
            return undef if exists($headers{'transfer-encoding'}) ||
                !defined($headers{'content-length'}) ||
                $headers{'content-length'} !~ /\A[1-9][0-9]{0,4}\z/;
            $header_bytes = $end + 4; $body_bytes = 0 + $headers{'content-length'};
            return undef if $header_bytes + $body_bytes > 65536;
        }
        if (length($response) >= $header_bytes + $body_bytes) {
            return undef unless length($response) == $header_bytes + $body_bytes;
            return status_version(substr($response, $header_bytes));
        }
    }
    return undef;
}
sub probe_status {
    my ($ip, $port, $deadline) = @_;
    my ($socket, $state) = connect_once($ip, $port, $deadline);
    return ($state, undef) unless $socket;
    my $request = "GET /api/status HTTP/1.0\r\nHost: $ip:$port\r\nConnection: close\r\n\r\n";
    my $version = send_bytes($socket, $request, $deadline) ? read_status($socket, $deadline) : undef;
    my $closed = close($socket);
    return defined($version) && $closed ? ('ready', $version) : ('unknown', undef);
}
sub read_regular {
    my ($path, $maximum) = @_;
    sysopen(my $file, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or die "Cannot safely open local file.\n";
    binmode($file);
    my @before = stat($file);
    unless (@before && S_ISREG($before[2]) && $before[7] > 0 && $before[7] <= $maximum) {
        close($file); die "Local file type or size is invalid.\n";
    }
    my $bytes = '';
    while (length($bytes) < $before[7]) {
        my $got = sysread($file, my $part, $before[7] - length($bytes));
        unless (defined($got) && $got > 0) { close($file); die "Local file read failed.\n"; }
        $bytes .= $part;
    }
    my $extra = sysread($file, my $tail, 1);
    my @after = stat($file);
    my $closed = close($file);
    die "Local file changed or could not be closed.\n" unless defined($extra) && $extra == 0 && $closed &&
        @after && join(':', @before[0,1,2,7,9,10]) eq join(':', @after[0,1,2,7,9,10]);
    return $bytes;
}
sub verified_payload {
    my ($directory) = @_;
    my $manifest = read_regular("$directory/SHA256SUMS", 256);
    die "SHA256SUMS must contain exactly the release ELF checksum.\n" unless
        $manifest =~ /\A([a-f0-9]{64})  (TostonSync v(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.elf)\n\z/;
    my ($expected, $name) = ($1, $2);
    my $bytes = read_regular("$directory/$name", 16 * 1024 * 1024);
    die "ELF checksum does not match. Nothing was sent.\n" unless
        substr($bytes, 0, 4) eq "\x7fELF" && sha256_hex($bytes) eq $expected;
    return $bytes;
}
sub send_payload {
    my ($ip, $bytes) = @_;
    my $deadline = clock_now() + 5;
    my ($socket, $state) = connect_once($ip, 9021, $deadline);
    return 0 unless $socket;
    my $sent = send_bytes($socket, $bytes, $deadline);
    my $ended = $sent && clock_now() < $deadline && shutdown($socket, 1);
    my $closed = close($socket);
    return $sent && $ended && $closed;
}
sub launch {
    my ($ip, $port, $directory) = @_;
    my ($state, $version) = probe_status($ip, $port, clock_now() + 2);
    if ($state eq 'ready') {
        print "Already running v$version. To update, use Settings > Update from a file.\n";
        return 0;
    }
    if ($state ne 'refused') {
        print "TostónSync status is uncertain. Nothing was sent. Check the PS5 IP and known web port.\n";
        return 1;
    }
    my $bytes = eval { verified_payload($directory) };
    if ($@) { print $@; return 1; }
    unless (send_payload($ip, $bytes)) {
        print "The single send did not finish. Start is UNKNOWN. No retry was sent.\n";
        return 1;
    }
    print "File sent once. Waiting for TostónSync…\n";
    my $deadline = clock_now() + 30;
    while (clock_now() < $deadline) {
        my $probe_end = clock_now() + 2;
        $probe_end = $deadline if $probe_end > $deadline;
        ($state, $version) = probe_status($ip, $port, $probe_end);
        if ($state eq 'ready') { print "TostónSync v$version is running.\n"; return 0; }
        my $left = $deadline - clock_now();
        sleep($left < 1 ? $left : 1) if $left > 0;
    }
    print "TostónSync did not become ready within 30 seconds. No retry was sent.\n";
    return 1;
}
sub main {
    binmode(STDOUT, ':encoding(UTF-8)'); $| = 1;
    print "PS5 IPv4 address: "; my $ip = <STDIN>;
    return 1 unless defined($ip); $ip =~ s/\r?\n\z//;
    unless ($ip =~ /\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/ &&
            !grep { $_ > 255 } split(/\./, $ip)) { print "Invalid IPv4 address.\n"; return 1; }
    print "Known TostónSync web port [1993] (not the loader port): "; my $port = <STDIN>;
    return 1 unless defined($port); $port =~ s/\r?\n\z//; $port = '1993' if $port eq '';
    unless ($port =~ /\A[1-9][0-9]{0,4}\z/ && $port <= 65535 && $port != 9021) {
        print "Invalid web port. The loader must not be probed.\n"; return 1;
    }
    my $directory = abs_path(@ARGV ? shift(@ARGV) : dirname($0));
    unless (defined($directory)) { print "Cannot locate the release folder.\n"; return 1; }
    return launch($ip, 0 + $port, $directory);
}
exit(main()) unless caller;
