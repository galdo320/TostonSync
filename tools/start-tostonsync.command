#!/bin/sh
exec /usr/bin/perl -x "$0" "$@"
#!perl
use strict;
use warnings;
use utf8;
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use JSON::PP;
use Digest::SHA qw(sha256_hex);
my $repository = abs_path(dirname(__FILE__) . '/..');
die "Cannot locate the launcher repository.\n" unless defined($repository);
open(my $library, '<:encoding(UTF-8)', "$repository/Start TostónSync.command") or die "Cannot read the bounded Mac launcher.\n";
my $source = do { local $/; <$library> }; close($library) or die "Cannot close the bounded Mac launcher.\n";
# Load only the trusted repository Perl body, not its double-click shell preamble.
$source =~ s/\A.*?^#!perl\n//ms or die "Invalid Mac launcher header.\n";
eval $source;
die "Cannot load the bounded Mac launcher.\n" if $@ || !defined(&launch) || !defined(&main);
{
    no warnings qw(redefine once);
    *verified_payload = sub {
        my ($directory) = @_;
        my $raw = read_regular("$directory/update-manifest.json", 4096);
        my $initial = JSON::PP->new->utf8->decode($raw);
        my $name = ref($initial) eq 'HASH' ? $initial->{asset} : undef;
        die "Invalid signed ELF asset name. Nothing was sent.\n" unless defined($name) && !ref($name) &&
            $name =~ /\ATostonSync-v(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.elf\z/;
        open(my $verified, '-|', 'python3', "$repository/tools/sign_release.py", 'verify',
             '--elf', "$directory/$name", '--manifest', "$directory/update-manifest.json",
             '--signature', "$directory/update-manifest.sig") or die "Cannot run signature verification.\n";
        my $output = do { local $/; <$verified> };
        my $ok = close($verified);
        die "Signature verification failed. Nothing was sent.\n" unless $ok;
        my $signed = JSON::PP->new->utf8->decode($output);
        die "Invalid verifier result. Nothing was sent.\n" unless ref($signed) eq 'HASH' &&
            $signed->{result} eq 'PASS_SIGNATURE_AND_ASSETS' && $signed->{schema} == 3 &&
            $signed->{asset} eq $name && $signed->{asset_sha256} =~ /\A[a-f0-9]{64}\z/;
        my $bytes = read_regular("$directory/$name", 16 * 1024 * 1024);
        die "ELF checksum does not match. Nothing was sent.\n" unless
            length($bytes) == $signed->{asset_size} && substr($bytes, 0, 4) eq "\x7fELF" &&
            sha256_hex($bytes) eq $signed->{asset_sha256};
        return $bytes;
    };
}
exit(main()) unless caller;
