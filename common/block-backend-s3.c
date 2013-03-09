#include "common.h"
#include "log.h"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "utils.h"

#include "block-backend.h"
#include "obj-store.h"

#ifdef S3_BACKEND

#define AMAZON_S3_URL_SUFFIX    ".s3.amazonaws.com"

#define GET             "GET"
#define PUT             "PUT"
#define HEAD            "HEAD"
#define DEL             "DELETE"

struct _BHandle {
    char  block_id[41];
    FILE *fp;    /* only used for write */
    int   rw_type;
};

typedef struct {
    const char *id;
    const char *bucket_name;
    const char *key_id;
    const char *key;
} S3Priv;

BHandle *
block_backend_s3_open_block (BlockBackend *bend,
                               const char *block_id,
                               int rw_type)
{
    BHandle *handle;

    handle = g_new0(BHandle, 1);
    memcpy(handle->block_id, block_id, 41);
    handle->rw_type = rw_type;

    if (rw_type == BLOCK_WRITE) {
        handle->fp = tmpfile();
        if (handle->fp == NULL)
            return NULL;
    }

    return handle;
}

static char *get_httpdate()
{
    static char atime[256];
    time_t now = time(NULL);
    struct tm *gtime;

    gtime = gmtime(&now);
    memset(atime, 0, sizeof(atime));
    strftime(atime, sizeof(atime), "%a, %d %b %Y %H:%M:%S +0000", gtime);
    return atime;
}

static char *b64encode(const unsigned char *md, int len)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    char *buf;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, len);
    BIO_get_mem_ptr(b64, &bptr);

    buf = (char *)malloc(bptr->length);
    memcpy(buf, bptr->data, bptr->length - 1);
    buf[bptr->length - 1] = 0;

    BIO_free_all(b64);
    return buf;
}

static char *
do_get_signature(BlockBackend *bend, const char *str)
{
    S3Priv *priv = bend->be_priv;
    HMAC_CTX ctx;
    unsigned char md[256];
    unsigned len;

    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, priv->key, strlen(priv->key), EVP_sha1());
    HMAC_Update(&ctx, (unsigned char *)str, strlen(str));
    HMAC_Final(&ctx, (unsigned char *)md, &len);
    HMAC_CTX_cleanup(&ctx);

    return b64encode(md, len);
}

static char *
get_signature(BlockBackend *bend, char *resource, int resource_size,
              char **date, const char *method, const char *block_id)
{
    S3Priv *priv = bend->be_priv;
    char req[2048];

    *date = get_httpdate();
    memset(resource, 0, resource_size);

    snprintf(resource, resource_size, "%s/%s", priv->bucket_name, block_id);

    snprintf(req, sizeof(req), "%s\n\n%s\n%s\n%s%s/%s",
             method, "", *date, "", "", resource);

    return do_get_signature(bend, req);
}

static size_t write_block(void *ptr, size_t size, size_t nmemb, void *stream)
{
    memcpy(stream, ptr, size * nmemb);
    return size * nmemb;
}

static int
s3_do_get(BlockBackend *bend, const char *signature, const char *date,
          const char *res, char *data, int *len)
{
    S3Priv *priv = bend->be_priv;
    char buf[1024];
    CURL *curl = NULL;
    struct curl_slist *list = NULL;
    int ret;

    curl = curl_easy_init();

    snprintf(buf, sizeof(buf), "Date: %s", date);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Authorization: AWS %s:%s", priv->key_id, signature);
    list = curl_slist_append(list, buf);

    snprintf(buf, sizeof(buf), "http://%s/%s", AMAZON_S3_URL_SUFFIX, res);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_block);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);

    ret = curl_easy_perform(curl);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return ret;
}

int
block_backend_s3_read_block (BlockBackend *bend, BHandle *handle,
                               void *buf, int len)
{
    char resource[1024];
    char *signature, *date = NULL;

    if (handle->rw_type == BLOCK_WRITE) {
        g_warning("[S3 backend] Couldn't read a write-only block\n");
        return -1;
    }

    signature = get_signature(bend, resource, sizeof(resource), &date, GET,
                              handle->block_id);

    return s3_do_get(bend, signature, date, resource, buf, &len);
}

int
block_backend_s3_write_block (BlockBackend *bend,
                                BHandle *handle,
                                const void *buf, int len)
{
    return write(fileno(handle->fp), buf, len);
}

static size_t
read_block(void *ptr, size_t size, size_t nmemb, void *stream)
{
    return fread(ptr, size, nmemb, stream);
}

static int
s3_do_put(BlockBackend *bend, BHandle *handle, const char *sig,
          const char *date, const char *res)
{
    S3Priv *priv = bend->be_priv;
    struct curl_slist *list = NULL;
    struct stat st;
    char buf[1024];
    CURL *curl = NULL;
    int ret;

    fstat(fileno(handle->fp), &st);

    curl = curl_easy_init();

    snprintf(buf, sizeof(buf), "Content-Type: text/plain");
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "x-amz-acl: %s", "public-read");
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Date: %s", date);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Authorization: AWS %s:%s", priv->key_id, sig);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "x-amz-meta-size: %lu", st.st_size);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "x-amz-meta-commit: %d", 1);
    list = curl_slist_append(list, buf);

    snprintf(buf, sizeof(buf), "http://%s/%s", AMAZON_S3_URL_SUFFIX, res);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_block);
    curl_easy_setopt(curl, CURLOPT_READDATA, handle->fp);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)st.st_size);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);

    ret = curl_easy_perform(curl);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return ret;
}

int
block_backend_s3_commit_block (BlockBackend *bend, BHandle *handle)
{
    char resource[1024];
    char *signature, *date = NULL;

    if (handle->rw_type == BLOCK_READ) {
        g_warning("[S3 backend] Couldn't write a read-only block\n");
        return -1;
    }

    signature = get_signature(bend, resource, sizeof(resource), &date, PUT,
                              handle->block_id);

    return s3_do_put(bend, handle, signature, date, resource);
}

int
block_backend_s3_close_block (BlockBackend *bend, BHandle *handle)
{
    if (handle->rw_type == BLOCK_WRITE)
        return fclose(handle->fp);

    return 0;
}

static size_t
get_commit(void *ptr, size_t size, size_t nmemb, void *stream)
{
    int *commit = (int *)stream;

    if (strncmp(ptr, "x-amz-meta-commit: ", 19) == 0)
        *commit = atoi(ptr + 19);

    return size * nmemb;
}

static int s3_do_head(BlockBackend *bend, const char *sig,
                      const char *date, const char *res)
{
    S3Priv *priv = bend->be_priv;
    char buf[1024];
    CURL *curl = NULL;
    struct curl_slist *list = NULL;
    int ret = 0;
    int commit;

    curl = curl_easy_init();

    snprintf(buf, sizeof(buf), "Date: %s", date);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Authorization: AWS %s:%s", priv->key_id, sig);
    list = curl_slist_append(list, buf);

    snprintf(buf, sizeof(buf), "http://%s/%s", AMAZON_S3_URL_SUFFIX, res);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, get_commit);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &commit);

    ret = curl_easy_perform(curl);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);

    return ret ? 0 : commit;
}

gboolean
block_backend_s3_block_exists (BlockBackend *bend, const char *block_sha1)
{
    char resource[1024];
    char *signature, *date = NULL;
    int ret;

    signature = get_signature(bend, resource, sizeof(resource), &date, HEAD,
                              block_sha1);

    ret = s3_do_head(bend, signature, date, resource);

    return ret ? TRUE : FALSE;
}

static int s3_do_delete(BlockBackend *bend, const char *sig, const char *date, const char *res)
{
    S3Priv *priv = bend->be_priv;
    char buf[1024];
    CURL *curl = NULL;
    struct curl_slist *list = NULL;
    int ret;

    curl = curl_easy_init();

    snprintf(buf, sizeof(buf), "Date: %s", date);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Authorization: AWS %s:%s", priv->key_id, sig);
    list = curl_slist_append(list, buf);

    snprintf(buf, sizeof(buf), "http://%s/%s", AMAZON_S3_URL_SUFFIX, res);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_URL, buf);

    ret = curl_easy_perform(curl);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);

    return ret;
}

int
block_backend_s3_remove_block (BlockBackend *bend,
                                 const char *block_id)
{
    char resource[1024];
    char *signature, *date = NULL;

    signature = get_signature(bend, resource, sizeof(resource),
                              &date, DEL, block_id);

    return s3_do_delete(bend, signature, date, resource);
}

static size_t
get_meta(void *ptr, size_t size, size_t nmemb, void *stream)
{
    uint32_t *s = (uint32_t *)stream;

    if (strncmp(ptr, "x-amz-meta-size: ", 17) == 0)
        *s = atol(ptr + 17);

    return size * nmemb;
}

static int s3_do_stat(BlockBackend *bend, const char *sig,
                      const char *date, const char *res, uint32_t *size)
{
    S3Priv *priv = bend->be_priv;
    char buf[1024];
    CURL *curl = NULL;
    struct curl_slist *list = NULL;
    int ret;

    curl = curl_easy_init();

    snprintf(buf, sizeof(buf), "Date: %s", date);
    list = curl_slist_append(list, buf);
    snprintf(buf, sizeof(buf), "Authorization: AWS %s:%s", priv->key_id, sig);
    list = curl_slist_append(list, buf);

    snprintf(buf, sizeof(buf), "http://%s/%s", AMAZON_S3_URL_SUFFIX, res);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, get_meta);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, size);

    ret = curl_easy_perform(curl);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);

    return ret;
}

BMetadata *
block_backend_s3_stat_block (BlockBackend *bend,
                               const char *block_id)
{
    BMetadata *bmeta;
    char resource[1024];
    char *signature, *date = NULL;
    uint32_t size;
    int ret;

    bmeta = g_new0(BMetadata, 1);
    memcpy(bmeta->id, block_id, 41);

    signature = get_signature(bend, resource, sizeof(resource), &date, HEAD,
                              block_id);

    ret = s3_do_stat(bend, signature, date, resource, &size);

    if (!ret)
        bmeta->size = size;

    return bmeta;
}

BMetadata *
block_backend_s3_stat_block_by_handle (BlockBackend *bend,
                                         BHandle *handle)
{
    BMetadata *bmeta;
    char resource[1024];
    char *signature, *date = NULL;
    uint32_t size;
    int ret;

    bmeta = g_new0(BMetadata, 1);
    memcpy(bmeta->id, handle->block_id, 41);

    signature = get_signature(bend, resource, sizeof(resource), &date, HEAD,
                              handle->block_id);

    ret = s3_do_stat(bend, signature, date, resource, &size);

    if (!ret)
        bmeta->size = size;

    return bmeta;
}

void
block_backend_s3_block_handle_free (BlockBackend *bend, BHandle *handle)
{
    g_free(handle);
}

int
block_backend_s3_foreach_block (BlockBackend *bend,
                                  SeafBlockFunc process,
                                  void *user_data)
{
    return 0;
}

BlockBackend *block_backend_s3_new (const char *id, const char *bucket_name,
                                    const char *key_id, const char *key)
{
    BlockBackend *bend;
    S3Priv *priv;

    bend = g_new0(BlockBackend, 1);
    priv = g_new0(S3Priv, 1);
    bend->be_priv = priv;

    priv->id = g_strdup(id);
    priv->bucket_name = g_strdup(bucket_name);
    priv->key_id = g_strdup(key_id);
    priv->key = g_strdup(key);

    bend->open_block = block_backend_s3_open_block;
    bend->read_block = block_backend_s3_read_block;
    bend->write_block = block_backend_s3_write_block;
    bend->commit_block = block_backend_s3_commit_block;
    bend->close_block = block_backend_s3_close_block;
    bend->exists = block_backend_s3_block_exists;
    bend->remove_block = block_backend_s3_remove_block;
    bend->stat_block = block_backend_s3_stat_block;
    bend->stat_block_by_handle = block_backend_s3_stat_block_by_handle;
    bend->block_handle_free = block_backend_s3_block_handle_free;
    bend->foreach_block = block_backend_s3_foreach_block;

    curl_global_init(CURL_GLOBAL_ALL);

    return bend;
}

#else

BlockBackend *block_backend_s3_new (const char *id, const char *bucket_name,
                                    const char *key_id, const char *key)
{
    seaf_warning ("Amazon S3 backend is not enabled\n");
    return NULL;
}

#endif /* S3_BACKEND */
