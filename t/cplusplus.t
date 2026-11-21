#! /usr/bin/env perl

use strict;
use warnings;
use Test::More;

plan skip_all => "c++ not found"
    unless system("which c++ > /dev/null 2>&1") == 0;

my $binary_dir = $ENV{BINARY_DIR} || ".";
my $src = <<'EOT';
#include "quicly.h"
#if QUICLY_HAVE_FLEXICAST
#include "quicly/flexicast_cc.h"
#include "quicly/flexicast.h"
#endif
EOT

open my $fh, "|-", "c++", "-I$binary_dir/include", "-Iinclude", "-Ideps/picotls/include", "-c", "-x", "c++", "-Wall", "-o", "/dev/null", "-"
    or die "failed to spawn c++: $!";
print $fh $src;
my $ok = close $fh;

ok($ok);

done_testing;
