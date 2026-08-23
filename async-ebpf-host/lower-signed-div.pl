#!/usr/bin/env perl
use strict;
use warnings;

while (<>) {
    s/^(\s*)(%[-a-zA-Z$._0-9]+) = sdiv(?: exact)? (i(?:32|64)) ([^,]+), (.+)$/$1$2 = call $3 \@tcc_ebpf_sdiv_$3($3 $4, $3 $5)/;
    s/^(\s*)(%[-a-zA-Z$._0-9]+) = srem (i(?:32|64)) ([^,]+), (.+)$/$1$2 = call $3 \@tcc_ebpf_srem_$3($3 $4, $3 $5)/;
    print;
}
