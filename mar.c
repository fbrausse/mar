
#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>		/* getopt() */
#include <sys/stat.h>		/* stat() */
#include <libgen.h>		/* basename() */

#include <gio/gio.h>
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

enum overwrite {
	OVERWRITE_NONE,
	OVERWRITE_UNLINK,
	OVERWRITE_PLAIN,
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

static const char             *progname;
static GMimeEncodingConstraint encoding_constraint = GMIME_ENCODING_CONSTRAINT_7BIT;
static int                     dereference_symlinks = 0;
//static int recurse_subdirs = 0;
static int                     verbosity = 0;
static int                     extract_to_stdout = 0;
static const char             *preface       = NULL;
static const char             *postface      = NULL;
static const char             *subject       = NULL;
static const char             *boundary      = NULL;
static const char             *next_charset  = NULL;
static const char             *next_desc     = NULL;
static GMimeContentEncoding    next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
static int                     next_inline   = 0;
static const char             *next_mimetype = NULL;
static       char             *next_name     = NULL;
static enum action             action    = ACTION_NONE;
static enum overwrite          overwrite = OVERWRITE_NONE;

#define OPT_ACTIONS	"ctx" /* "Ar" */
#define OPT_FMODS	"C:d:e:im:n:"

static void set_action(enum action a)
{
	if (action != ACTION_NONE)
		FATAL(1,"only one of -" OPT_ACTIONS " may be specified\n");
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
	GMimeStream *stream = NULL;
	struct stat st;
	if (!strcmp(path, "-")) {
		stream = g_mime_stream_buffer_new(g_mime_stream_file_new(stdin),
		                                  GMIME_STREAM_BUFFER_CACHE_READ);
	} else if ((dereference_symlinks ? stat : lstat)(path, &st)) {
			FATAL(2,"error stat'ing path '%s' to input: %s\n",
			      path,strerror(errno));
	} else if (S_ISLNK(st.st_mode)) {
		FATAL(1,"refusing to handle symlink '%s' due "
		      "to '-H' not specified\n", path);
	} else if (S_ISREG(st.st_mode)) {
		stream = g_mime_stream_file_new_for_path(path, "rb");
	} else if (S_ISFIFO(st.st_mode)) {
		stream = g_mime_stream_buffer_new(g_mime_stream_file_new_for_path(path, "rb"),
		                                  GMIME_STREAM_BUFFER_CACHE_READ);
	} else {
		FATAL(1,"error: cannot handle non-regular file '%s'\n",
		      path);
	}

	GMimePart *part = g_mime_part_new();

	const char *disposition;
	if (!next_name)
		next_name = basename(path);
	if (next_inline)
		disposition = GMIME_DISPOSITION_INLINE;
	else {
		disposition = GMIME_DISPOSITION_ATTACHMENT;
		g_mime_part_set_filename(part, next_name);
	}
	g_mime_object_set_disposition(GMIME_OBJECT(part), disposition);

	if (next_desc)
		g_mime_part_set_content_description(part, next_desc);

	GMimeDataWrapper *data = g_mime_data_wrapper_new_with_stream(stream,
			GMIME_CONTENT_ENCODING_BINARY);
	g_object_unref(stream);
	g_mime_part_set_content_object(part, data);
	g_object_unref(data);

	int have_enc  = next_encoding != GMIME_CONTENT_ENCODING_DEFAULT;
	int have_type = next_mimetype != NULL;
	int have_cs   = next_charset  != NULL;

	gboolean gio_content_type_uncertain;
	gchar *gio_content_type = g_content_type_guess(path,NULL,0,&gio_content_type_uncertain);
	gchar *gio_mime_type = g_content_type_get_mime_type(gio_content_type);
	if (verbosity > 1)
		LOG("%s: gio %s content-type '%s', mime-type '%s'\n",path,
		    gio_content_type_uncertain ? "guesses" : "identifies",
		    gio_content_type, gio_mime_type);

	if (!have_type)
		next_mimetype = next_inline || have_cs ? DEFAULT_MIMETYPE_TEXT : gio_mime_type;

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

static GMimeObject * mar_create(int argc, char **argv)
{
	GMimeMultipart *mpart = g_mime_multipart_new();
	if (boundary)
		g_mime_multipart_set_boundary(mpart, boundary);
	if (preface)
		g_mime_multipart_set_preface(mpart, preface);
	if (postface)
		g_mime_multipart_set_postface(mpart, postface);

	do {
		GMimePart *part = mar_create_part(argv[optind++]);
		g_mime_multipart_add(mpart, GMIME_OBJECT(part));

		next_charset = NULL;
		next_desc = NULL;
		next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
		next_inline = 0;
		next_mimetype = NULL;
		next_name = NULL;

		int opt;
		while ((opt = getopt(argc, argv, ":" OPT_FMODS)) != -1)
			switch (opt) {
			/* fmods */
			case 'C': next_charset = optarg; break;
			case 'd': next_desc = optarg; break;
			case 'e': set_encoding(optarg); break;
			case 'i': next_inline = 1; break;
			case 'm': next_mimetype = optarg; break;
			case 'n': next_name = optarg; break;

			case ':': FATAL(1,"option '-%c' expects a parameter\n",optopt);
			case '?': FATAL(1,"unknown option '-%c'\n",optopt);
			}
	} while (optind < argc);

	return GMIME_OBJECT(mpart);
}

struct mar_idx {
	char **members;
	unsigned n_members;
	unsigned msg_id;
	unsigned part_id[1]; /* max depth: 1 */
};

#define MAR_IDX_INIT	{ NULL, 0, 0, { 0 }, }

static int mar_idx_find_filename(struct mar_idx *idx, const char *filename)
{
	if (!idx->n_members)
		return 1;
	for (unsigned i=0; i<idx->n_members; i++)
		if (!strcmp(idx->members[i], filename))
			return 1;
	return 0;
}

static void mar_list_cb(
	GMimeObject *parent, GMimeObject *part, gpointer user_data
) {
	GMimeContentType *content_type = g_mime_object_get_content_type(part);
	char *content_type_str = g_mime_content_type_to_string(content_type);
	const char *disposition = g_mime_object_get_disposition(part);
	const char *id = g_mime_object_get_content_id(part);
	struct mar_idx *idx = user_data;

	const char *filename = NULL;
	const char *description = NULL;
	GMimeContentEncoding encoding = GMIME_CONTENT_ENCODING_DEFAULT;
	GMimeStream *data_stream = NULL;

	// GType gtype = G_OBJECT_TYPE(part);

	const char *type = NULL;
	if (GMIME_IS_MESSAGE(part))
		type = "message";
	else if (GMIME_IS_PART(part)) {
		type = "part";
		description = g_mime_part_get_content_description(GMIME_PART(part));
		encoding = g_mime_part_get_content_encoding(GMIME_PART(part));
		filename = g_mime_part_get_filename(GMIME_PART(part));
		data_stream = g_mime_data_wrapper_get_stream(
				g_mime_part_get_content_object(GMIME_PART(part)));
	} else if (GMIME_IS_MULTIPART(part))
		type = "multipart";
	else if(GMIME_IS_MESSAGE_PART(part))
		type = "message-part";

	if (verbosity > 0 || (filename && mar_idx_find_filename(idx, filename)))
		LOG("%u/%u: type '%s', content type '%s', disposition: '%s', "
		    "id: '%s', filename: '%s', description: '%s', "
		    "encoding: '%s', size: %lld\n",
		    idx->msg_id, idx->part_id[0], type, content_type_str, disposition,
		    id, filename, description,
		    encoding_strs[encoding], (long long)g_mime_stream_length(data_stream));

	free(content_type_str);

	idx->part_id[0]++;
}

static void mar_extract_cb(
	GMimeObject *parent, GMimeObject *part, gpointer user_data
) {
	struct mar_idx *idx = user_data;

	if (!GMIME_IS_PART(part)) {
		LOG("warning: skipping non-MIME-part message\n");
		return;
	}

	GMimePart *p = GMIME_PART(part);
	GMimeDataWrapper *w = g_mime_part_get_content_object(p);
	if (!w) {
		if (verbosity > 1)
			LOG("warning: skipping MIME part w/o content\n");
		return;
	} 

	GMimeStream *ws = g_mime_data_wrapper_get_stream(w);

	const char *filename = g_mime_part_get_filename(p);
	if (!filename) {
		LOG("skipping MIME part w/o filename, sz: %lld\n",
		    (long long)g_mime_stream_length(ws));
		return;
	}

	char *filename_dup = strdup(filename);
	char *filename_base = basename(filename_dup);

	if (!mar_idx_find_filename(idx, filename)) {
		if (verbosity > 0)
			LOG("skipping non-mentioned MIME-part with filename '%s'\n",
			    filename);
		return;
	}

	if (strcmp(filename, filename_base))
		LOG("stripping path from '%s' -> '%s'\n",filename,filename_base);

	if (!extract_to_stdout) {
		struct stat st;
		if (lstat(filename_base, &st)) {
			if (errno != ENOENT)
				FATAL(1,"error stat'ing output path '%s': %s\n",
				      filename_base, strerror(errno));
		} else if (overwrite == OVERWRITE_UNLINK) {
			if (!S_ISREG(st.st_mode))
				FATAL(1,"refusing to unlink existing non-regular '%s'\n",
				      filename_base);
			if (unlink(filename_base))
				FATAL(1,"error unlinking '%s': '%s'\n",
				      filename_base, strerror(errno));
		} else if (overwrite != OVERWRITE_PLAIN) {
			FATAL(1,"refusing to overwrite existing '%s'\n",
			      filename_base);
		}
	}

	if (verbosity > 0)
		LOG("%s\n", filename_base);

	GMimeStream *s = g_mime_stream_filter_new(g_mime_data_wrapper_get_stream(w));
	GMimeFilter *f = g_mime_filter_basic_new(g_mime_data_wrapper_get_encoding(w), FALSE);
	g_mime_stream_filter_add(GMIME_STREAM_FILTER(s), f);
	GMimeStream *o = extract_to_stdout ? g_mime_stream_file_new(stdout)
	                                   : g_mime_stream_file_new_for_path(filename_base, "wb");
	if (!o)
		FATAL(1,"error opening '%s' for writing: %s\n", filename_base, strerror(errno));
	ssize_t r = g_mime_stream_write_to_stream(s, o);
	if (r == -1)
		FATAL(1,"error writing '%s': %s\n", filename_base, strerror(errno));
	g_object_unref(s);
	g_object_unref(o);

	free(filename_dup);
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
  -B BOUN  explicitely specify 'boundary' delimiter of the MIME message\n\
  -f FILE  read/write MIME message from/to FILE instead of stdin/stdout\n\
  -h       display this help message\n\
  -H       dereference symbolic links instead of aborting\n\
  -O       extract files to stdout\n\
  -p PRE   use PRE as multipart preface text\n\
  -P POST  use POST as multipart postface text\n\
  -s SUBJ  insert a 'Subject'-Header\n\
  -u       unlink existing files before writing\n\
  -U       overwrite (and don't unlink) existing files during extraction\n\
           (unsafe: this makes a difference for existing symlinks)\n\
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
  -i       disposition this part as 'inline', implies 'text/plain' (if not set)\n\
  -m TYPE  specifies the MIME-type of following file argument (only for -c, -r);\n\
           if not given, it will be guessed using libmagic(3) (if available) or\n\
           GIO (if available), defaults to '" DEFAULT_MIMETYPE "' except\n\
           for the case described for option '-e'\n\
  -n NAME  use string NAME for FILE in message, defaults to basename of FILE,\n\
           except for inline parts\n\
\n\
FILE can be the name of an existing file, pipe or \"-\" to denote stdin\n\
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
		opt = getopt(argc, argv, optind == 1 ? ":78bBfhHOpPsuUv" OPT_ACTIONS
		                                     : ":78bB:f:hHOup:P:s:Uv" OPT_FMODS);
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
			if (fstr)
				FATAL(1,"only one specification of '-f' is supported\n");
		case 'B':
		case 'p':
		case 'P':
		case 's':
			if (next_arg_f)
				FATAL(1,"only one of '-BfpPs' may be specified in the first parameter\n");
			next_arg_f = opt;
			break;
		case 'H': dereference_symlinks = 1; break;
		case 'h': FATAL_DO(0,print_help());
		case 'O': extract_to_stdout = 1; break;
//		case 'R': recurse_subdirs = 1; break;
		case 'u': overwrite = OVERWRITE_UNLINK; break;
		case 'U': overwrite = OVERWRITE_PLAIN; break;
		case 'v': verbosity++; break;

		/* fmods */
		case 'C': next_charset = optarg; break;
		case 'd': next_desc = optarg; break;
		case 'e': set_encoding(optarg); break;
		case 'i': next_inline = 1; break;
		case 'm': next_mimetype = optarg; break;
		case 'n': next_name = optarg; break;

		case ':': FATAL(1,"option '-%c' expects a parameter\n",optopt);
		case '?': FATAL(1,"unknown option '-%c'\n", optopt);
		}
		if (next_arg_f && optind != oldind) {
			if (optind >= argc)
				FATAL(1,"option '-%c' expects a parameter\n",
				      next_arg_f);
			char *arg = oldind == 1 ? argv[optind++] : optarg;
			switch (next_arg_f) {
			case 'B': boundary = arg; break;
			case 'f': fstr     = arg; break;
			case 'p': preface  = arg; break;
			case 'P': postface = arg; break;
			case 's': subject  = arg; break;
			}
			next_arg_f = 0;
		}
		if (opt < 0)
			break;
	}

	GMimeObject *mar;
	GMimeStream *s;
	switch (action) {
	case ACTION_NONE:
		FATAL(1,"no action specified, need one of -" OPT_ACTIONS "\n");
	case ACTION_CREATE: {
		if (optind >= argc)
			FATAL(1,"error: refusing to create empty MIME message\n");

		mar = mar_create(argc, argv);

		GMimeMessage *msg = g_mime_message_new(FALSE);
		g_mime_message_set_mime_part(msg, mar);
		if (subject)
			g_mime_message_set_subject(msg, subject);

		s = fstr ? g_mime_stream_file_new_for_path(fstr, "wb")
		         : g_mime_stream_file_new(stdout);

		g_mime_object_encode(GMIME_OBJECT(msg), encoding_constraint);
		g_mime_object_write_to_stream(GMIME_OBJECT(msg), s);

		g_object_unref(msg);
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
	case ACTION_EXTRACT: {
		s = fstr ? g_mime_stream_file_new_for_path(fstr, "rb")
		         : g_mime_stream_file_new(stdin);
		if (!s)
			FATAL(1,"error opening '%s' for reading: %s\n",
			      fstr ? fstr : "stdin", strerror(errno));

		GMimeObjectForeachFunc cb;
		cb = (action == ACTION_LIST) ? mar_list_cb : mar_extract_cb;

		GMimeParser *p = g_mime_parser_new_with_stream(s);
		struct mar_idx idx = MAR_IDX_INIT;
		idx.members = argv + optind;
		idx.n_members = argc - optind;
		for (; !g_mime_parser_eos(p); idx.msg_id++) {
			if (!(mar = g_mime_parser_construct_part(p)))
				FATAL(1,"error reading input as MIME part\n");
			if (GMIME_IS_MULTIPART(mar))
				g_mime_multipart_foreach(GMIME_MULTIPART(mar),
				                         cb, &idx);
			else if (GMIME_IS_PART(mar))
				cb(NULL, mar, &idx);
			else
				FATAL(1,"error: input is not a (multi)part "
				        "MIME message\n");
			g_object_unref(mar);
		}
		g_object_unref(p);
		g_object_unref(s);
		break;
	}
	}

	return 0;
}
