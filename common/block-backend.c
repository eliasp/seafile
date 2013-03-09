
#include "common.h"

#include "block-backend.h"

extern BlockBackend *
block_backend_fs_new (const char *block_dir, const char *tmp_dir);

#ifdef SEAFILE_SERVER
extern BlockBackend *
block_backend_ceph_new (const char *ceph_conf, const char *poolname);

extern BlockBackend *
block_backend_s3_new (const char *bucket_name, const char *key_id,
                      const char *key);
#endif

BlockBackend*
load_filesystem_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *tmp_dir;
    char *block_dir;
    
    block_dir = g_key_file_get_string (config, "block_backend", "block_dir", NULL);
    if (!block_dir) {
        g_warning ("Block dir not set in config.\n");
        return NULL;
    }

    tmp_dir = g_key_file_get_string (config, "block_backend", "tmp_dir", NULL);
    if (!tmp_dir) {
        g_warning ("Block tmp dir not set in config.\n");
        return NULL;
    }

    bend = block_backend_fs_new (block_dir, tmp_dir);

    g_free (block_dir);
    g_free (tmp_dir);
    return bend;
}

#ifdef SEAFILE_SERVER
BlockBackend*
load_ceph_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *ceph_conf;
    char *poolname;

    ceph_conf = g_key_file_get_string (config, "block_backend",  "ceph_config", NULL);
    if (!ceph_conf) {
        g_warning("Ceph config file not set in config.\n");
        return NULL;
    }

    poolname = g_key_file_get_string (config, "block_backend", "pool", NULL);
    if (!poolname) {
        g_warning("Ceph poolname not set in config.\n");
        return NULL;
    }

    bend = block_backend_ceph_new (ceph_conf, poolname);

    g_free (ceph_conf);
    g_free (poolname);

    return bend;
}

BlockBackend*
load_s3_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *bucket_name;
    char *key_id;
    char *key;
    char *id;

    id = g_key_file_get_string (config, "awsid", "s3_config", NULL);
    if (!id) {
        g_warning("Amazon S3 config file not set in config.\n");
        return NULL;
    }

    bucket_name = g_key_file_get_string (config, "bucket_name", "s3_config", NULL);
    if (!bucket_name) {
        g_warning("Amazon S3 config file not set in config.\n");
        g_free(id);
        return NULL;
    }

    key_id = g_key_file_get_string (config, "key_id", "s3_config", NULL);
    if (!key_id) {
        g_warning("Amazon S3 config file not set in config.\n");
        g_free(id);
        g_free(bucket_name);
        return NULL;
    }

    key = g_key_file_get_string (config, "key", "s3_config", NULL);
    if (!key) {
        g_warning("Amamzon S3 config file not set in config.\n");
        g_free(id);
        g_free(bucket_name);
        g_free(key_id);
        return NULL;
    }

    bend = block_backend_s3_new (bucket_name, key_id, key);

    return bend;
}
#endif

BlockBackend*
load_block_backend (GKeyFile *config)
{
    char *backend;
    BlockBackend *bend;

    backend = g_key_file_get_string (config, "block_backend", "name", NULL);
    if (!backend) {
        return NULL;
    }

    if (strcmp(backend, "filesystem") == 0) {
        bend = load_filesystem_block_backend(config);
        g_free (backend);
        return bend;
    }
#ifdef SEAFILE_SERVER
    else if (strcmp(backend, "ceph") == 0) {
        bend = load_ceph_block_backend(config);
        g_free(backend);
        return bend;
    }
    else if (strcmp(backend, "s3") == 0) {
        bend = load_s3_block_backend(config);
        g_free(backend);
    }
#endif

    g_warning ("Unknown backend\n");
    return NULL;
}
