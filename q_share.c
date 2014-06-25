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
/opt/gcc-4.8.1/bin/gcc -o q_share q_share.c nfs_sec.c -lnsl
*/

#include <nfs/export.h>
#include <sharefs/share.h>

/* libshare_nfs.c:printarg() example of struct exportdata using krb5
/export/user/1:
        ex_version = 2
        ex_path = /export/user/1
        ex_pathlen = 15
        ex_flags: (0x01) NOSUID
        ex_anon = 60001
        ex_seccnt = 2

                s_secinfo = krb5i
                s_flags: (0x04) M_RW
                s_window = 30000
                s_rootid = 0
                s_rootcnt = 0

                s_secinfo = krb5p
                s_flags: (0x04) M_RW
                s_window = 30000
                s_rootid = 0
                s_rootcnt = 0
*/
int main(int argc, char **argv) {
	struct exportdata export;
	struct secinfo sec[2];
	int ret = 0;
	struct share sh;
	int arg;

	if(argc < 2)
		return 1;

	/* Prep our static structures */

	nfs_getseconfig_byname("krb5i", &sec[0].s_secinfo); // func not available
	nfs_getseconfig_byname("krb5p", &sec[1].s_secinfo);

	sec[0].s_flags = M_RW;
	sec[0].s_window = 30000;
	sec[0].s_rootid = 0;
	sec[0].s_rootcnt = 0;
	
	sec[1].s_flags = M_RW;
	sec[1].s_window = 30000;
	sec[1].s_rootid = 0;
	sec[1].s_rootcnt = 0;

	export.ex_version = EX_CURRENT_VERSION;
	export.ex_flags = EX_NOSUID;
	export.ex_anon = UID_NOBODY;
	export.ex_seccnt = 2;
	export.ex_secinfo = sec;
	export.ex_index = NULL;
	export.ex_log_buffer = NULL;
	export.ex_log_bufferlen = 0;
	export.ex_tag = NULL;
	export.ex_taglen = 0;

	sh.sh_res = "-";
	sh.sh_fstype = "nfs";
	sh.sh_opts = "nosuid,sec=krb5i,sec=krb5p";
	sh.sh_descr = "q_share"; // Leave our mark in the descr
	sh.sh_size = 0;
	sh.sh_next = NULL;

	for(arg = 1; arg < argc; arg++) {
		export.ex_path = argv[arg];
		export.ex_pathlen = strlen(export.ex_path) + 1;

		if(ret = exportfs(argv[arg], &export)) {
			fprintf(stderr, "Failed to export %s: %d\n", argv[arg], ret);
			return ret;
		}

		/* exported! Now update sharetab */
		sh.sh_path = argv[arg];
		if(ret = _sharefs(SHAREFS_ADD, &sh)) {
			fprintf(stderr, "Failed to update sharetab %s: %d\n", argv[arg], ret);
			return ret;
		}
	}

	return 0;
}
