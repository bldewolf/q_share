/*
Copyright (C) 2014 Brian De Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* to build on omnios:
/opt/gcc-4.8.1/bin/gcc -o q_unshare q_unshare.c -lnsl
*/

#include <nfs/export.h>
#include <sharefs/share.h>

int main(int argc, char **argv) {
	int ret = 0;
	struct share sh;
	int arg;

	if(argc < 2)
		return 1;

	/* Prep our static structures */

	sh.sh_res = "-";
	sh.sh_fstype = "nfs";
	sh.sh_opts = "nosuid,sec=krb5i,sec=krb5p";
	sh.sh_descr = "q_share"; // Leave our mark in the descr
	sh.sh_size = 0;
	sh.sh_next = NULL;

	for(arg = 1; arg < argc; arg++) {
		if(ret = exportfs(argv[arg], NULL)) {
			fprintf(stderr, "Failed to export %s: %d\n", argv[arg], ret);
			return ret;
		}

		/* exported! Now update sharetab */
		sh.sh_path = argv[arg];
		if(ret = _sharefs(SHAREFS_REMOVE, &sh)) {
			fprintf(stderr, "Failed to update sharetab %s: %d\n", argv[arg], ret);
			return ret;
		}
	}

	return 0;
}
