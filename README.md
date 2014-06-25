q\_share
=======

Quick 'n' dirty Illumos share(1M) "replacement"


Share(1M) has a history of being incredibly slow when lots (>100) of ZFS
filesystems are involved.  In Solaris 10, setting an environment variable
(SHARE\_NOINUSE\_CHECK) caused share(1M) to skip a lot of checks that slowed it
down, making it bearable again (see [this
thread](http://marc.info/?t=127704941600003&r=1&w=2)).

Unfortunately, somehow SHARE\_NOINUSE\_CHECK disappeared from Illumos, leaving
the native share(1M) slow without any knobs to make it faster.  After
struggling for a few days to convince share(1M) to be faster (and under the
advice of some friendly fellows in #illumos), I boiled down sharing to its two
syscalls in a standalone binary that beats share(1M) by magntitudes of speed
and has yet to prove itself to be unsafe.

It's not a general replacement for share(1M), but a good starting point if you
want reasonable boot times and don't feel like digging through illumos-gate.


#### "Why is nfs\_sec.c included?"

This file is included so we can call nfs\_getseconfig\_byname.  This populates
some rpcsec structures that contain more magic numbers than I am willing to
hard code (if someone knows what the seconfig sc\_qop field is for, please tell
me).
