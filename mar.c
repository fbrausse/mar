
#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>		/* getopt() */
#include <sys/stat.h>		/* stat() */
#include <libgen.h>		/* basename() */

#include <gmime/gmime.h>

#define DEFAULT_ENC		"quoted-printable"
#define DEFAULT_MIMETYPE_TEXT	"text/plain"
#define DEFAULT_MIMETYPE	"application/octet-stream"

enum action {
	ACTION_NONE = -1,
//	ACTION_CONCAT,
	ACTION_CREATE,
//	ACTION_APPEND,
	ACTION_LIST,
	ACTION_EXTRACT,
};

static const char *const encoding_strs[] = {
	[GMIME_CONTENT_ENCODING_7BIT           ] = "7bit",
	[GMIME_CONTENT_ENCODING_8BIT           ] = "8bit",
	[GMIME_CONTENT_ENCODING_BINARY         ] = "binary",
	[GMIME_CONTENT_ENCODING_BASE64         ] = "base64",
	[GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE] = "quoted-printable",
	[GMIME_CONTENT_ENCODING_UUENCODE       ] = "uuencode",
//	[GMIME_CONTENT_ENCODING_               ] = "yencode",
};

static const char *progname;
static GMimeEncodingConstraint encoding_constraint = GMIME_ENCODING_CONSTRAINT_7BIT;
static int dereference_symlinks = 0;
//static int recurse_subdirs = 0;
static int verbosity = 0;
static const char *next_charset = NULL;
static const char *next_desc = NULL;
static GMimeContentEncoding next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
static const char *next_mimetype = NULL;
static       char *next_name = NULL;
static enum action action = ACTION_NONE;
static FILE *fin = NULL, *fout = NULL;

static void set_action(enum action a)
{
	if (action != ACTION_NONE)
		FATAL(1,"only one of -Acrtx may be specified\n");
	action = a;
}

static void set_encoding(const char *e)
{
	next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
	for (unsigned i=0; i<ARRAY_SIZE(encoding_strs); i++) {
		if (!encoding_strs[i])
			continue;
		if (strstr(encoding_strs[i], e) != encoding_strs[i])
			continue;
		if (next_encoding != GMIME_CONTENT_ENCODING_DEFAULT)
			FATAL(1,"encoding '%s' is ambiguous\n",e);
		next_encoding = i;
	}
	if (next_encoding == GMIME_CONTENT_ENCODING_DEFAULT)
		FATAL(1,"unknown encoding '%s'\n",e);
}

static GMimePart * mar_create_part(char *path)
{
	char *orgpath = path;
	static char pathbuf[PATH_MAX+1];
	GMimeStream *stream = NULL;
	while (1) {
		struct stat st;
		if (lstat(path, &st))
			FATAL(2,"error stat'ing path '%s' to input: %s\n",path,strerror(errno));
		if (S_ISLNK(st.st_mode)) {
			if (!dereference_symlinks)
				FATAL(1,"refusing to handle symlink '%s' due to '-H' not specified\n",path);
			ssize_t l = readlink(path, pathbuf, sizeof(pathbuf)-1);
			if (l < 0)
				FATAL(1,"error reading symlink '%s': %s\n",path,strerror(errno));
			pathbuf[l] = '\0';
			path = pathbuf;
			continue;
		}
		if (S_ISREG(st.st_mode)) {
			stream = g_mime_stream_file_new_for_path(path, "rb");
			break;
		}
		FATAL(1,"error: cannot handle non-regular file '%s'\n",path);
	};

	GMimePart *part = g_mime_part_new();

	if (!next_name)
		next_name = basename(orgpath);
	g_mime_part_set_filename(part, next_name);

	if (next_desc)
		g_mime_part_set_content_description(part, next_desc);

	GMimeDataWrapper *data = g_mime_data_wrapper_new_with_stream(stream, GMIME_CONTENT_ENCODING_BINARY);
	g_object_unref(stream);
	g_mime_part_set_content_object(part, data);
	g_object_unref(data);

	int have_enc  = next_encoding != GMIME_CONTENT_ENCODING_DEFAULT;
	int have_type = next_mimetype != NULL;
	int have_cs   = next_charset  != NULL;

	gboolean gio_content_type_uncertain;
	gchar *gio_content_type = g_content_type_guess(path,NULL,0,&gio_content_type_uncertain);
	gchar *gio_mime_type = g_content_type_get_mime_type(gio_content_type);
	if (verbosity > 1) {
		LOG("%s: gio %s content-type '%s', mime-type '%s'\n",path,
		    gio_content_type_uncertain ? "guesses" : "identifies",
		    gio_content_type, gio_mime_type);
	}

	if (!have_type)
		next_mimetype = have_cs ? DEFAULT_MIMETYPE_TEXT : gio_mime_type;

	GMimeContentType *mt = g_mime_content_type_new_from_string(next_mimetype);
	GMimeContentType *gio_mt = g_mime_content_type_new_from_string(gio_mime_type);
	const char *mt1 = g_mime_content_type_get_media_type(mt);
	const char *mt2 = g_mime_content_type_get_media_type(gio_mt);
	const char *mst1 = g_mime_content_type_get_media_subtype(mt);
	const char *mst2 = g_mime_content_type_get_media_subtype(gio_mt);
	if (!gio_content_type_uncertain
	    && (strcmp(mt1, mt2)
	        || ((verbosity > 1 || strncmp(mst2, "x-", 2) || !strncmp(mst1, "x-", 2))
	            && strcmp(gio_mime_type, next_mimetype))))
		LOG("%s: warning: gio identified mime-type '%s' instead of '%s'\n",
		    path,gio_mime_type,next_mimetype);
	g_object_unref(gio_mt);
	g_free(gio_content_type);
	g_free(gio_mime_type);

	if (!have_cs)
		next_charset = g_mime_locale_charset();
	if (!strcmp("text", g_mime_content_type_get_media_type(mt)))
		g_mime_content_type_set_parameter(mt, "charset", next_charset);
	g_mime_object_set_content_type(GMIME_OBJECT(part), mt);
	g_object_unref(mt);

	if (!have_enc) {
		next_encoding = g_mime_part_get_best_content_encoding(part, encoding_constraint);
		if (verbosity > 0 && next_encoding != GMIME_CONTENT_ENCODING_DEFAULT)
			LOG("%s: using content-encoding '%s'\n",path,encoding_strs[next_encoding]);
	}
	g_mime_part_set_content_encoding(part, next_encoding);

	return part;
}

#define OPT_FMODS	"C:d:e:m:n:"

static GMimeObject * mar_create(int argc, char **argv)
{
	GMimeMultipart *mpart = g_mime_multipart_new();

	do {
		g_mime_multipart_add(mpart, GMIME_OBJECT(mar_create_part(argv[optind++])));

		next_charset = NULL;
		next_desc = NULL;
		next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
		next_mimetype = NULL;
		next_name = NULL;

		int opt;
		while ((opt = getopt(argc, argv, ":" OPT_FMODS)) != -1)
			switch (opt) {
			/* fmods */
			case 'C': next_charset = optarg; break;
			case 'd': next_desc = optarg; break;
			case 'e': set_encoding(optarg); break;
			case 'm': next_mimetype = optarg; break;
			case 'n': next_name = optarg; break;

			case ':': FATAL(1,"option '-%c' expects a parameter\n",optopt);
			case '?': FATAL(1,"unknown option '-%c'\n", optopt);
			}
	} while (optind < argc);

	return GMIME_OBJECT(mpart);
}

#define USAGE		"\
create : %s [-]c[OPTS] [-OPTS] [[-FMODS] [--] FILE [[-FMODS] [--] FILE [...]]]\n\
list   : %s [-]t[OPTS] [-OPTS] [--] [MEMBER [MEMBER [...]]]\n\
extract: %s [-]x[OPTS] [-OPTS] [--] [MEMBER [MEMBER [...]]]\n\
"
/*
  -A       append / concatenate MIME messages\n\
  -r       append files to MIME message, parameters mean the same as for '-c'\n\
  -R       enable recursion into directories instead of aborting\n\*/
#define HELP_MSG	"\
ACTION is one of:\n\
  -c       create MIME message from files\n\
  -t       list contents of MIME message\n\
  -x       extract contents of MIME message\n\
\n\
OPTS are any of:\n\
  -7       encode for 7bit channel, encode data 7bit-clean; this is the default\n\
  -8       encode for 8bit channel, just encode embedded zeros\n\
  -b       encode for binary-safe channel, don't force any encoding\n\
  -f FILE  read/write MIME message from/to FILE instead of stdin/stdout\n\
  -h       display this help message\n\
  -H       dereference symbolic links instead of aborting\n\
  -O       extract files to stdout\n\
  -v       verbose mode of operation, use twice for greater effect\n\
\n\
FMODS are any of:\n\
  -C CS    implies TYPE 'text/*' ('" DEFAULT_MIMETYPE_TEXT "' if not given), defines charset of\n\
           the MIME part for the next FILE, defaults to the locale(1)'s charset\n\
           '%s'\n\
  -d DESC  use string DESC as Content-Description MIME header value\n\
  -e ENC   specifies the content-transfer-encoding to use: 7bit, 8bit, binary,\n\
           base64, quoted-printable, uuencode;\n\
           defaults to '" DEFAULT_ENC "' for TYPE 'text/*', 'base64' otherwise\n\
  -m TYPE  specifies the MIME-type of following file argument (only for -c, -r);\n\
           if not given, it will be guessed using libmagic(3) (if available) or\n\
           GIO (if available), defaults to '" DEFAULT_MIMETYPE "' except\n\
           for the case described for option '-e'\n\
  -n NAME  use string NAME for FILE in message, defaults to basename of FILE\n\
\n\
MIME archiver, written by Franz Brauße <dev@karlchenofhell.org>. License: GPLv2.\n\
"

static void print_usage(void)
{
	fprintf(stderr,USAGE,progname,progname,progname);
}

static void print_help(void)
{
	print_usage();
	fprintf(stderr, "\n");
	fprintf(stderr, HELP_MSG, g_mime_locale_charset());
}

#define OPT_ACTIONS	"ctx" /* "Ar" */

int main(int argc, char **argv)
{
	progname = argv[0];

	g_mime_init(0);
	atexit(g_mime_shutdown);

	if (argc <= 1)
		FATAL_DO(1,print_usage());

	int n = strlen(argv[1]);
	char action_arg[n+2];

	if (argv[1][0] != '-') {
		sprintf(action_arg, "-%s", argv[1]);
		argv[1] = action_arg;
	}

	char *fstr = NULL;
	int opt;
	for (int next_arg_f = 0;;) {
		int oldind = optind;
		opt = getopt(argc, argv, optind == 1 ? ":78bfhHOv" OPT_ACTIONS
		                                     : ":78bf:hHOv" OPT_FMODS);
		switch (opt) {
		/* actions */
//		case 'A': set_action(ACTION_CONCAT); break;
		case 'c': set_action(ACTION_CREATE); break;
//		case 'r': set_action(ACTION_APPEND); break;
		case 't': set_action(ACTION_LIST); break;
		case 'x': set_action(ACTION_EXTRACT); break;

		/* options */
		case '7': encoding_constraint = GMIME_ENCODING_CONSTRAINT_7BIT; break;
		case '8': encoding_constraint = GMIME_ENCODING_CONSTRAINT_8BIT; break;
		case 'b': encoding_constraint = GMIME_ENCODING_CONSTRAINT_BINARY; break;
		case 'f':
			if (next_arg_f || fstr)
				FATAL(1,"only one specification of '-f' is supported\n");
			if (oldind == 1)
				next_arg_f = 1;
			else
				fstr = optarg;
			break;
		case 'H': dereference_symlinks = 1; break;
		case 'h': FATAL_DO(0,print_help());
		case 'O': fout = stdout; break;
//		case 'R': recurse_subdirs = 1; break;
		case 'v': verbosity++; break;

		/* fmods */
		case 'C': next_charset = optarg; break;
		case 'd': next_desc = optarg; break;
		case 'e': set_encoding(optarg); break;
		case 'm': next_mimetype = optarg; break;
		case 'n': next_name = optarg; break;

		case ':': FATAL(1,"option '-%c' expects a parameter\n",optopt);
		case '?': FATAL(1,"unknown option '-%c'\n", optopt);
		}
		if (next_arg_f && optind != oldind) {
			if (optind >= argc)
				FATAL(1,"option '-f' expects a filename argument\n");
			fstr = argv[optind++];
			next_arg_f = 0;
		}
		if (opt < 0)
			break;
	}

	GMimeObject *mar;
	GMimeStream *s;
	switch (action) {
	case ACTION_NONE:
		FATAL(1,"no action specified, need one of -Acrtx\n");
	case ACTION_CREATE: {
		if (optind >= argc)
			FATAL(1,"error: refusing to create empty MIME message\n");

		mar = mar_create(argc, argv);

		s = fstr ? g_mime_stream_file_new_for_path(fstr, "wb")
		         : g_mime_stream_file_new(stdout);

		g_mime_object_encode(mar, encoding_constraint);
		g_mime_object_write_to_stream(mar, s);

		g_object_unref(mar);
		g_object_unref(s);
		break;
	}/*
	case ACTION_APPEND:
		fin = stdin;
		if (fstr) {
			fin = fout = fopen(fstr, "rwb");
		} else {
			fout = stdout;
		}
		break;
	case ACTION_CONCAT:
		if (!fstr)
			FATAL(1,"need explicit parameter '-f' for action -A\n");
		fout = fopen(fstr, "rwb");
		break;*/
	case ACTION_LIST:
	case ACTION_EXTRACT:
		fin = fstr ? fopen(fstr, "rb") : stdin;
		break;
	}

	
}