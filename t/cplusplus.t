#! /usr/bin/env perl

use strict;
use warnings;
use Test::More;

plan skip_all => "c++ not found"
    unless system("which c++ > /dev/null 2>&1") == 0;

my $flexicast_off = defined $ENV{BUILD_FLEXICAST} && $ENV{BUILD_FLEXICAST} =~ /^(?:OFF|0|FALSE|NO)$/i;
my @args = qw(c++ -Iinclude -Ideps/picotls/include --include quicly.h);
push @args, qw(--include quicly/flexicast_cc.h --include quicly/flexicast.h)
    unless $flexicast_off;
push @args, qw(-c -x c++ -Wall /dev/null);

is system(@args), 0;

done_testing;
