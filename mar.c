
#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>		/* getopt() */
#include <sys/stat.h>		/* stat() */
#include <libgen.h>		/* basename() */
#include <stdint.h>		/* uint32_t */
#include <strings.h>		/* strncasecmp() */
#include <sys/stat.h>		/* lstat() */

#if (HAVE_LIBMAGIC - 0)
# include <magic.h>
#endif

#include <gio/gio.h>
#include <gmime/gmime.h>

#define MAGIC_BUFFER_SZ		(64 * 1024)
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

struct strmap {
	unsigned v;
	const char *s;
};

static const struct strmap encoding_strs[] = {
	{ GMIME_CONTENT_ENCODING_7BIT           , "7bit" },
	{ GMIME_CONTENT_ENCODING_8BIT           , "8bit" },
	{ GMIME_CONTENT_ENCODING_BINARY         , "binary" },
	{ GMIME_CONTENT_ENCODING_BASE64         , "base64" },
	{ GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE, "quoted-printable" },
	{ GMIME_CONTENT_ENCODING_UUENCODE       , "uuencode" },
//	{ GMIME_CONTENT_ENCODING_               , "yencode" },
};

static const struct strmap pubkeyalog_strs[] = {
	{ GMIME_PUBKEY_ALGO_RSA  , "rsa" },
	{ GMIME_PUBKEY_ALGO_RSA_E, "enc-rsa" },
	{ GMIME_PUBKEY_ALGO_RSA_S, "sign-rsa" },
	{ GMIME_PUBKEY_ALGO_ELG_E, "enc-elgamal" },
	{ GMIME_PUBKEY_ALGO_DSA  , "dsa" },
	{ GMIME_PUBKEY_ALGO_ELG  , "elgamal" },
};

static const struct strmap digestalgo_strs[] = {
	{ GMIME_DIGEST_ALGO_MD5      , "md5" },
	{ GMIME_DIGEST_ALGO_SHA1     , "sha-1" },
	{ GMIME_DIGEST_ALGO_RIPEMD160, "ripemd-160" },
	{ GMIME_DIGEST_ALGO_MD2      , "md2" },
	{ GMIME_DIGEST_ALGO_TIGER192 , "tiger-192" },
	{ GMIME_DIGEST_ALGO_HAVAL5160, "haval5-160" },
	{ GMIME_DIGEST_ALGO_SHA256   , "sha-256" },
	{ GMIME_DIGEST_ALGO_SHA384   , "sha-384" },
	{ GMIME_DIGEST_ALGO_SHA512   , "sha-512" },
	{ GMIME_DIGEST_ALGO_SHA224   , "sha-224" },
	{ GMIME_DIGEST_ALGO_MD4      , "md4" },
};

static const struct strmap certtrust_strs[] = {
	{ GMIME_CERTIFICATE_TRUST_NONE     , "none" },
	{ GMIME_CERTIFICATE_TRUST_NEVER    , "never" },
	{ GMIME_CERTIFICATE_TRUST_UNDEFINED, "undefined" },
	{ GMIME_CERTIFICATE_TRUST_MARGINAL , "marginal" },
	{ GMIME_CERTIFICATE_TRUST_FULLY    , "fully" },
	{ GMIME_CERTIFICATE_TRUST_ULTIMATE , "ultimate" },
};

static unsigned strmap_get_by_prefix(
	const struct strmap *map, size_t sz, const char *str, const char *desc
) {
	const struct strmap *ret = NULL;
	unsigned len = strlen(str);
	for (; sz; sz--, map++) {
		if (!strncasecmp(map->s, str, len))
			continue;
		if (ret)
			FATAL(1,"%s '%s' is ambiguous\n",desc,str);
		ret = map;
	}
	if (!ret)
		FATAL(1,"unknown %s '%s'\n",desc,str);
	return ret->v;
}

static const char * strmap_find_by_val(
	const struct strmap *map, size_t sz, unsigned v
) {
	for (; sz; sz--, map++)
		if (map->v == v)
			return map->s;
	return NULL;
}

#define STRMAP_GET_BY_PREFIX(map,str,desc)	strmap_get_by_prefix(map,ARRAY_SIZE(map),str,desc)
#define STRMAP_FIND_BY_VAL(map,v)		strmap_find_by_val(map,ARRAY_SIZE(map),v)

static const char             *progname;
static GMimeEncodingConstraint encoding_constraint = GMIME_ENCODING_CONSTRAINT_7BIT;
static int                     dereference_symlinks = 0;
//static int recurse_subdirs = 0;
static int                     verbosity = 0;
static int                     extract_to_stdout = 0;
static int                     sign          = 0;
static int                     do_crypt      = 0;
static GPtrArray              *recipients    = NULL;
static GMimeDigestAlgo         digest        = GMIME_DIGEST_ALGO_DEFAULT;
static GMimeCryptoContext     *crypto_ctx    = NULL;
static const char             *preface       = NULL;
static const char             *postface      = NULL;
static const char             *boundary      = NULL;
static const char             *next_charset  = NULL;
static const char             *next_desc     = NULL;
static GMimeContentEncoding    next_encoding = GMIME_CONTENT_ENCODING_DEFAULT;
static int                     next_inline   = 0;
static const char             *next_mimetype = NULL;
static       char             *next_name     = NULL;
static enum action             action    = ACTION_NONE;
static enum overwrite          overwrite = OVERWRITE_NONE;
static GMimeMessage           *msg = NULL;
#if (HAVE_LIBMAGIC - 0)
static magic_t                 magic = NULL;
#endif

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
	next_encoding = STRMAP_GET_BY_PREFIX(encoding_strs,e,"encoding");
}

static GMimePart * mar_create_part(char *path)
{
	GMimeStream *stream = NULL;
	struct stat st;
	int have_path = 0;
	int can_seek = -1;
	if (!strcmp(path, "-")) {
		stream = g_mime_stream_file_new(stdin);
	} else if ((dereference_symlinks ? stat : lstat)(path, &st)) {
		FATAL(2,"error stat'ing path '%s' to input: %s\n",
		      path,strerror(errno));
	} else if (S_ISLNK(st.st_mode)) {
		FATAL(1,"refusing to handle symlink '%s' due "
		      "to '-H' not specified\n", path);
	} else if (S_ISREG(st.st_mode)) {
		stream = g_mime_stream_file_new(fopen(path, "rb"));
		can_seek = 1;
		have_path = 1;
	} else if (S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode)) {
		stream = g_mime_stream_file_new(fopen(path, "rb"));
		can_seek = 0;
	} else {
		FATAL(1,"error: cannot handle non-regular file '%s'\n",
		      path);
	}
	if (can_seek < 0)
		can_seek = g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_CUR) != -1;
	if (!can_seek) {
		stream = g_mime_stream_buffer_new(stream,
		                                  GMIME_STREAM_BUFFER_CACHE_READ);
		can_seek = 1;
	}

	GMimePart *part = g_mime_part_new();

	const char *disposition;
	if (next_inline)
		disposition = GMIME_DISPOSITION_INLINE;
	else {
		disposition = GMIME_DISPOSITION_ATTACHMENT;
		if (have_path && !next_name)
			next_name = basename(path);
		if (next_name)
			g_mime_part_set_filename(part, next_name);
	}
	g_mime_object_set_disposition(GMIME_OBJECT(part), disposition);

	if (next_desc)
		g_mime_part_set_content_description(part, next_desc);

	int have_enc  = next_encoding != GMIME_CONTENT_ENCODING_DEFAULT;
	int have_type = next_mimetype != NULL;
	int have_cs   = next_charset  != NULL;

static char magic_buf[MAGIC_BUFFER_SZ];
	size_t magic_rd = 0;
	while (!g_mime_stream_eos(stream) && sizeof(magic_buf) - magic_rd) {
		ssize_t r = g_mime_stream_read(stream, magic_buf + magic_rd,
		                               sizeof(magic_buf) - magic_rd);
		if (r < 0)
			FATAL(1,"error reading '%s': %s\n",path,strerror(errno));
		magic_rd += r;
		if (!r)
			break;
	}

	const char *magic_mimetype = NULL;
	gchar *gio_content_type;
	gboolean gio_content_type_uncertain;
#if (HAVE_LIBMAGIC - 0)
	if (magic) {
		if (have_path)
			magic_mimetype = magic_file(magic, path);
		else
			magic_mimetype = magic_buffer(magic, magic_buf, magic_rd);
		if (!magic_mimetype)
			LOG("libmagic error: %s\n", magic_error(magic));
	}
#endif
	gio_content_type = g_content_type_guess(have_path ? path : NULL,
	                                        (guchar *)magic_buf, magic_rd,
	                                        &gio_content_type_uncertain);
	gchar *gio_mime_type = g_content_type_get_mime_type(gio_content_type);

	GMimeDataWrapper *data = g_mime_data_wrapper_new_with_stream(stream,
			GMIME_CONTENT_ENCODING_BINARY);
	g_mime_part_set_content_object(part, data);
	g_object_unref(data);
	g_object_unref(stream);

	if (verbosity > 1) {
		if (magic_mimetype)
			LOG("%s: libmagic reports mime-type '%s'\n",path,
			    magic_mimetype);
		LOG("%s: gio %s content-type '%s', mime-type '%s'\n",path,
		    gio_content_type_uncertain ? "guesses" : "identifies",
		    gio_content_type, gio_mime_type);
	}

	const char *mt_certain = NULL;
	if (!have_type) {
		next_mimetype = magic_mimetype;
		mt_certain = magic_mimetype;
	}
	if (!next_mimetype) {
		next_mimetype = gio_mime_type;
		mt_certain = gio_content_type_uncertain ? NULL : gio_mime_type;
	}

	GMimeContentType *mt = g_mime_content_type_new_from_string(next_mimetype);
	const char *mt1 = g_mime_content_type_get_media_type(mt);
	const char *mst1 = g_mime_content_type_get_media_subtype(mt);
	if ((next_inline || have_cs) && mt_certain && strcmp(mt1, "text"))
		LOG("%s: warning: declared with %s, but discovered mime-type is non-text '%s'\n",
		    path,next_inline ? have_cs ? "-i/-c" : "-i" : "-c",
		    next_mimetype);

	if (mt_certain) {
		GMimeContentType *c_mt = g_mime_content_type_new_from_string(mt_certain);
		const char *mt2 = g_mime_content_type_get_media_type(c_mt);
		const char *mst2 = g_mime_content_type_get_media_subtype(c_mt);
		if (mt_certain
		    && (strcmp(mt1, mt2)
		        || ((verbosity > 1 || strncmp(mst2, "x-", 2) || !strncmp(mst1, "x-", 2))
		            && strcmp(mt_certain, next_mimetype))))
			LOG("%s: warning: identified mime-type '%s' instead of '%s'\n",
			    path,mt_certain,next_mimetype);
		g_object_unref(c_mt);
	}
	g_free(gio_content_type);
	g_free(gio_mime_type);

	if (!strcmp("text", mt1)) {
		const char *cs = g_mime_content_type_get_parameter(mt, "charset");
		if (have_cs && cs && strcmp(next_charset, cs)) {
			LOG("%s: warning: declared charset '%s' but identified '%s'\n",
			    path,next_charset,cs);
		} else if (!have_cs) {
			next_charset = cs ? cs : g_mime_locale_charset();
			if (verbosity > 1)
				LOG("%s: using charset '%s'\n",path,next_charset);
		}
		/* workaround bug in gmime: free's cs before strdup'ing next_charset */
		if (next_charset != cs)
			g_mime_content_type_set_parameter(mt, "charset", next_charset);
	}
	if (verbosity > 0) {
		char *mts = g_mime_content_type_to_string(mt);
		LOG("%s: using content-type '%s'\n",path,mts);
		free(mts);
	}
	g_mime_object_set_content_type(GMIME_OBJECT(part), mt);
	g_object_unref(mt);

	if (!have_enc) {
		next_encoding = g_mime_part_get_best_content_encoding(part, encoding_constraint);
		if (verbosity > 0 && next_encoding != GMIME_CONTENT_ENCODING_DEFAULT)
			LOG("%s: using content-encoding '%s'\n",path,
			    STRMAP_FIND_BY_VAL(encoding_strs,next_encoding));
	}
	g_mime_part_set_content_encoding(part, next_encoding);

	return part;
}

static GMimeObject * mar_create(int argc, char **argv, const char *user_id)
{
	GMimeMultipart *mpart = do_crypt ? GMIME_MULTIPART(g_mime_multipart_encrypted_new())
	                      : sign ? GMIME_MULTIPART(g_mime_multipart_signed_new())
	                      : g_mime_multipart_new();
	if (boundary)
		g_mime_multipart_set_boundary(mpart, boundary);
	if (preface)
		g_mime_multipart_set_preface(mpart, preface);
	if (postface)
		g_mime_multipart_set_postface(mpart, postface);

	do {
		char *path = argv[optind++];
		GMimePart *part = mar_create_part(path);
		int r = 0;
		GError *err = NULL;
		if (do_crypt)
			r = g_mime_multipart_encrypted_encrypt(GMIME_MULTIPART_ENCRYPTED(mpart),
			                                       GMIME_OBJECT(part),
			                                       crypto_ctx,
			                                       sign,
			                                       user_id,
			                                       digest,
			                                       recipients,
			                                       &err);
		else if (sign)
			r = g_mime_multipart_signed_sign(GMIME_MULTIPART_SIGNED(mpart),
			                                 GMIME_OBJECT(part),
			                                 crypto_ctx,
			                                 user_id,
			                                 digest,
			                                 &err);
		else
			g_mime_multipart_add(mpart, GMIME_OBJECT(part));
		if (r)
			FATAL(1,"%s: %s failed (%d): %s\n",path,
			      do_crypt ? "encrypting" : "signing",
			      err->code,err->message);

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
		GMimeDataWrapper *data_wrapper = g_mime_part_get_content_object(GMIME_PART(part));
		data_stream = data_wrapper ? g_mime_data_wrapper_get_stream(data_wrapper) : NULL;
	} else if (GMIME_IS_MULTIPART(part))
		type = "multipart";
	else if(GMIME_IS_MESSAGE_PART(part))
		type = "message-part";

	if (verbosity > 0 || (filename && mar_idx_find_filename(idx, filename)))
		LOG("%u/%u: type '%s', content type '%s', disposition: '%s', "
		    "id: '%s', filename: '%s', description: '%s', "
		    "encoding: '%s', "
		    "size: %lld\n",
		    idx->msg_id, idx->part_id[0], type, content_type_str, disposition,
		    id, filename, description,
		    STRMAP_FIND_BY_VAL(encoding_strs,encoding),
		    data_stream ? (long long)g_mime_stream_length(data_stream) : -1LL);

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
	                                   : g_mime_stream_file_new(fopen(filename_base, "wb"));
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

#ifdef MAR_GPG_BINARY_PATH
# define HELP_MSG_GPG	"\
  -g       use RFC 2440 (OpenPGP) instead of RFC 2633 (PKCS#7, default) format\n"
# define OPT_GPG	"g"
#else
# define HELP_MSG_GPG
# define OPT_GPG
#endif

#define HELP_MSG	"\
ACTION is one of:\n\
  -c       create MIME message from files\n\
  -t       list contents of MIME message\n\
  -x       extract contents of MIME message\n\
\n\
OPTS are any of:\n\
  -0       'encode' for binary-safe channel, don't force any encoding\n\
  -7       encode for 7bit channel, encode data 7bit-clean; this is the default\n\
  -8       encode for 8bit channel, just encode embedded zeros\n\
  -b BCC   \n\
  -B BOUN  explicitely specify 'boundary' delimiter of the MIME message\n\
  -c CC    \n\
  -D DIGA  use digest algorithm DIGA\n\
  -E       en-/decrypt message content (requires -t for encryption)\n\
  -f FILE  read/write MIME message from/to FILE instead of stdin/stdout\n\
  -F FROM  mail address of sender, set as 'From' header\n" \
HELP_MSG_GPG "\
  -h       display this help message\n\
  -H       dereference symbolic links instead of aborting\n\
  -O       extract files to stdout\n\
  -p PRE   use PRE as multipart preface text\n\
  -P POST  use POST as multipart postface text\n\
  -s SUBJ  insert a 'Subject'-Header\n\
  -S       add/verify signature (requires -F for signing)\n\
  -t TO    mail address of recipient, insert as 'To'-Header\n\
  -u       unlink existing (regular) files before writing\n\
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
           base64, quoted-printable, uuencode; still subject to -078\n\
  -i       disposition this part as 'inline', implies 'text/plain' (if not set)\n\
  -m TYPE  specifies the MIME-type of following file argument (only for -c);\n\
           if not given, it will be guessed using libmagic(3) (if available) or\n\
           GIO (if available), defaults to '" DEFAULT_MIMETYPE "' except\n\
           for the case described for option '-e'\n\
  -n NAME  use string NAME for FILE in message, defaults to basename of FILE,\n\
           except for inline parts\n\
\n\
FILE can be the name of an existing file, pipe or \"-\" to denote stdin.\n\
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
	fprintf(stderr, "\nCompiled / linked with:\n");
#if (HAVE_LIBMAGIC - 0)
	fprintf(stderr, "\tlibmagic header %d.%d / library %d.%d\n",
		MAGIC_VERSION   / 100, MAGIC_VERSION   % 100,
		magic_version() / 100, magic_version() % 100);
#endif
	fprintf(stderr, "\tglib header %d.%d.%d / library %d.%d.%d\n",
		GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION,
		glib_major_version, glib_minor_version, glib_micro_version);
	fprintf(stderr, "\tgmime header %d.%d.%d / library %d.%d.%d\n",
		GMIME_MAJOR_VERSION, GMIME_MINOR_VERSION, GMIME_MICRO_VERSION,
		gmime_major_version, gmime_minor_version, gmime_micro_version);
#ifdef MAR_GPG_BINARY_PATH
	fprintf(stderr, "\tGnuPG binary path: %s\n", MAR_GPG_BINARY_PATH);
#endif
}

static void mar_extract_recipients(InternetAddressList *l)
{
	unsigned n = internet_address_list_length(l);
	for (unsigned i=0; i<n; i++) {
		InternetAddress *a = internet_address_list_get_address(l, i);
		if (INTERNET_ADDRESS_IS_GROUP(a)) {
			InternetAddressGroup *g = INTERNET_ADDRESS_GROUP(a);
			mar_extract_recipients(internet_address_group_get_members(g));
		} else {
			if (!INTERNET_ADDRESS_IS_MAILBOX(a)) {
				char *s = internet_address_to_string(a, FALSE);
				LOG("warning: cannot encrypt for non-mailbox internet address '%s'\n",s);
				free(s);
			}
			InternetAddressMailbox *m = INTERNET_ADDRESS_MAILBOX(a);
			g_ptr_array_add(recipients, (void *)internet_address_mailbox_get_addr(m));
		}
	}
}

static gboolean mar_pwd_request_cb(
	GMimeCryptoContext *ctx, const char *user_id, const char *prompt_ctx,
	gboolean reprompt, GMimeStream *response, GError **err
) {
	return FALSE;
}

int main(int argc, char **argv)
{
	progname = argv[0];

#if (HAVE_LIBMAGIC - 0)
	magic = magic_open(
		MAGIC_MIME_TYPE | MAGIC_MIME_ENCODING | MAGIC_RAW |
		MAGIC_ERROR | MAGIC_NO_CHECK_COMPRESS | MAGIC_NO_CHECK_ELF |
		MAGIC_NO_CHECK_TAR
	);
	if (!magic)
		LOG("warning: error initializing libmagic: %s\n",
		    strerror(errno));
	else if (magic_load(magic, NULL)) {
		LOG("warning: error initializing libmagic default database: %s\n",
		    magic_error(magic));
		magic_close(magic);
		magic = NULL;
	}
	errno = 0;
#endif

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
	int smime = 1;
	int opt;
	for (int next_arg_f = 0;;) {
		int oldind = optind;
		opt = getopt(argc, argv,
		             optind == 1 ? ":078BDEfF" OPT_GPG "hHOpPsSuUv" OPT_ACTIONS
		                         : ":078BD:Eb:c:f:F:" OPT_GPG "hHOup:P:s:St:Uv" OPT_FMODS);
		switch (opt) {
		/* actions */
//		case 'A': set_action(ACTION_CONCAT); break;
		case 'c':
			if (oldind == 1) {
				set_action(ACTION_CREATE);
				msg = g_mime_message_new(FALSE);
			} else if (!msg)
				FATAL(1,"invalid mode of operation: not creating a MIME message\n");
			else
				g_mime_message_add_recipient(msg, GMIME_RECIPIENT_TYPE_CC, NULL, optarg);
			break;
//		case 'r': set_action(ACTION_APPEND); break;
		case 't':
			if (oldind == 1)
				set_action(ACTION_LIST);
			else if (!msg)
				FATAL(1,"invalid mode of operation: not creating a MIME message\n");
			else
				g_mime_message_add_recipient(msg, GMIME_RECIPIENT_TYPE_TO, NULL, optarg);
			break;
		case 'x': set_action(ACTION_EXTRACT); break;

		/* options */
		case '0': encoding_constraint = GMIME_ENCODING_CONSTRAINT_BINARY; break;
		case '7': encoding_constraint = GMIME_ENCODING_CONSTRAINT_7BIT; break;
		case '8': encoding_constraint = GMIME_ENCODING_CONSTRAINT_8BIT; break;
		case 'b':
			if (!msg)
				FATAL(1,"invalid mode of operation: not creating a MIME message\n");
			g_mime_message_add_recipient(msg, GMIME_RECIPIENT_TYPE_BCC, NULL, optarg);
			break;
		case 'E': do_crypt = 1; break;
		case 'f':
			if (fstr)
				FATAL(1,"only one specification of '-f' is supported\n");
		case 'B':
		case 'D':
		case 'F':
		case 'p':
		case 'P':
		case 's':
			if (next_arg_f)
				FATAL(1,"only one of '-BDfFpPs' may be specified in the first parameter\n");
			next_arg_f = opt;
			break;
		case 'g': smime = 0; break;
		case 'H': dereference_symlinks = 1; break;
		case 'h': FATAL_DO(0,print_help());
		case 'O': extract_to_stdout = 1; break;
//		case 'R': recurse_subdirs = 1; break;
		case 'S': sign = 1; break;
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
			if (oldind == 1 && optind >= argc)
				FATAL(1,"option '-%c' expects a parameter\n",
				      next_arg_f);
			char *arg = oldind == 1 ? argv[optind++] : optarg;
			switch (next_arg_f) {
			case 'B': boundary = arg; break;
			case 'D': digest = STRMAP_GET_BY_PREFIX(digestalgo_strs,arg,"digest algorithm"); break;
			case 'f': fstr     = arg; break;
			case 'F': g_mime_message_set_sender(msg, arg); break;
			case 'p': preface  = arg; break;
			case 'P': postface = arg; break;
			case 's': g_mime_message_set_subject(msg, arg); break;
			}
			next_arg_f = 0;
		}
		if (opt < 0)
			break;
	}

	if (sign || do_crypt) {
		if (smime) {
			crypto_ctx = g_mime_pkcs7_context_new(mar_pwd_request_cb);
		} else {
#ifdef MAR_GPG_BINARY_PATH
			crypto_ctx = g_mime_gpg_context_new(mar_pwd_request_cb, MAR_GPG_BINARY_PATH);
#else
			FATAL(1,"%s compiled without MAR_GPG_BINARY_PATH, no OpenPGP support\n",progname);
#endif
		}
		if (!crypto_ctx)
			FATAL(1,"error: unable to create %s crypto context, does gmime support it?\n",
			      smime ? "PKCS#7" : "GnuPG");
	}

	GMimeObject *mar;
	GMimeStream *s;
	switch (action) {
	case ACTION_NONE:
		FATAL(1,"no action specified, need one of -" OPT_ACTIONS "\n");
	case ACTION_CREATE: {
		if (sign && !g_mime_message_get_sender(msg))
			FATAL(1,"error: signed message (-S) needs a known sender (-F)\n");
		if (do_crypt) {
			recipients = g_ptr_array_new();
			mar_extract_recipients(g_mime_message_get_recipients(msg, GMIME_RECIPIENT_TYPE_TO));
			mar_extract_recipients(g_mime_message_get_recipients(msg, GMIME_RECIPIENT_TYPE_CC));
			mar_extract_recipients(g_mime_message_get_recipients(msg, GMIME_RECIPIENT_TYPE_BCC));
			if (!recipients->len)
				FATAL(1,"error: encrypting a message (-E) needs known recipients (-t, -c or -b)\n");
		}
		if (optind >= argc)
			FATAL(1,"error: refusing to create empty MIME message\n");
		mar = mar_create(argc, argv, g_mime_message_get_sender(msg));

		g_mime_message_set_mime_part(msg, mar);

		s = fstr ? g_mime_stream_file_new(fopen(fstr, "wb"))
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
		s = fstr ? g_mime_stream_file_new(fopen(fstr, "rb"))
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
			GError *err = NULL;
			if (GMIME_IS_MULTIPART_ENCRYPTED(mar)) {
				if (do_crypt) {
					GMimeObject *dec = g_mime_multipart_encrypted_decrypt(
							GMIME_MULTIPART_ENCRYPTED(mar),
							crypto_ctx, NULL, &err);
					g_object_unref(mar);
					if (!dec) {
						FATAL_IF(action == ACTION_EXTRACT,1,
						         "error decrypting MIME part: %s\n",err->message);
						g_error_free(err);
						continue;
					}
					mar = dec;
				} else {
					FATAL_IF(action == ACTION_EXTRACT,1,
					         "error decrypting MIME part due to missing -E\n");
					g_object_unref(mar);
					continue;
				}
			} else if (GMIME_IS_MULTIPART_SIGNED(mar)) {
				if (do_crypt || sign) {
					GMimeSignatureList *l = g_mime_multipart_signed_verify(
							GMIME_MULTIPART_SIGNED(mar),
							crypto_ctx, &err);
					if (err) {
						FATAL_IF(action == ACTION_EXTRACT,1,
						         "error verifying signed MIME part: %s\n",
						         err->message);
						g_error_free(err);
						g_object_unref(mar);
						continue;
					}
					unsigned n = g_mime_signature_list_length(l);
					unsigned sign_ok = 0;
					for (unsigned i=0; i<n; i++) {
						GMimeSignature *s = g_mime_signature_list_get_signature(l, i);
						GMimeCertificate *c = g_mime_signature_get_certificate(s);
						if (verbosity > 1) {
							static char ctime_buf1[128], ctime_buf2[128];
							struct tm cre_tm, exp_tm;
							time_t cre = g_mime_certificate_get_created(c);
							time_t exp = g_mime_certificate_get_expires(c);
							if (cre == -1 || !strftime(ctime_buf1, sizeof(ctime_buf1), "%c", localtime_r(&cre, &cre_tm)))
								sprintf(ctime_buf1, "<unknown>");
							if (exp == -1 || !strftime(ctime_buf2, sizeof(ctime_buf2), "%c", localtime_r(&exp, &exp_tm)))
								sprintf(ctime_buf2, "<unknown>");
							LOG("signature cert: key: %s, digest: %s, issuer: '%s', serial: %s, fprint: %s, key id: %s, valid %s til %s, name: '%s', email: %s\n",
							    STRMAP_FIND_BY_VAL(pubkeyalog_strs,g_mime_certificate_get_pubkey_algo(c)),
							    STRMAP_FIND_BY_VAL(digestalgo_strs,g_mime_certificate_get_digest_algo(c)),
							    g_mime_certificate_get_issuer_name(c),
							    g_mime_certificate_get_issuer_serial(c),
							    g_mime_certificate_get_fingerprint(c),
							    g_mime_certificate_get_key_id(c),
							    ctime_buf1, ctime_buf2,
							    g_mime_certificate_get_name(c),
							    g_mime_certificate_get_email(c));
						}
						switch (g_mime_signature_get_status(s)) {
						case GMIME_SIGNATURE_STATUS_GOOD:
							sign_ok++;
							break;
						case GMIME_SIGNATURE_STATUS_BAD:
						case GMIME_SIGNATURE_STATUS_ERROR:
							if (!verbosity)
								break;
							uint32_t errs = g_mime_signature_get_errors(s);
							LOG("error verifying signature:");
							do switch ((GMimeSignatureError)(errs & -errs)) {
							case GMIME_SIGNATURE_ERROR_NONE: fprintf(stderr, " none"); break;
							case GMIME_SIGNATURE_ERROR_EXPSIG: fprintf(stderr, " expired"); break;
							case GMIME_SIGNATURE_ERROR_NO_PUBKEY: fprintf(stderr, " no-public-key"); break;
							case GMIME_SIGNATURE_ERROR_EXPKEYSIG: fprintf(stderr, " key-expired"); break;
							case GMIME_SIGNATURE_ERROR_REVKEYSIG: fprintf(stderr, " key-revoked"); break;
							case GMIME_SIGNATURE_ERROR_UNSUPP_ALGO: fprintf(stderr, " algorithm-unsupported"); break;
							default: fprintf(stderr, " unknown"); break;
							} while ((errs ^= errs & -errs));
							fprintf(stderr, "\n");
							break;
						}
					}
					g_object_unref(l);
					if (sign_ok == n) {
						if (verbosity)
							LOG("successfully verified all %u signatures for MIME part\n", sign_ok);
					} else {
						if (verbosity)
							LOG("verification of %u / %u signatures failed\n", n - sign_ok, n);
						if (action == ACTION_EXTRACT)
							FATAL(1,"error: not all signatures could be verified\n");
					}
				} else {
					FATAL_IF(action == ACTION_EXTRACT,1,
					         "error verifying signed MIME part due to missing -S\n");
				}
			}
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
