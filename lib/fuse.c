/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"
#include <linux/fuse.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>


static guint name_hash(const struct node *node)
{
    return g_str_hash(node->name) ^ node->parent;
}

static gint name_compare(const struct node *node1, const struct node *node2)
{
    return
        node1->parent == node2->parent &&
        strcmp(node1->name, node2->name) == 0;
}

static struct node *new_node(fino_t parent, const char *name)
{
    struct node *node = g_new0(struct node, 1);
    node->name = strdup(name);
    node->parent = parent;
    return node;
}

static int free_node(struct node *node)
{
    g_free(node->name);
    g_free(node);
    return 1;
}

static inline struct node *get_node(fino_t ino)
{
    return (struct node *) ino;
}

static inline fino_t get_ino(struct node *node)
{
    return (fino_t) node;
}


static fino_t find_node(struct fuse *f, fino_t parent, char *name, int create)
{
    struct node *node;
    struct node tmp;
    
    tmp.name = name;
    tmp.parent = parent;

    node = g_hash_table_lookup(f->nametab, &tmp);
    if(node != NULL)
        return get_ino(node);

    if(!create)
        return (fino_t) -1;

    node = new_node(parent, name);
    g_hash_table_insert(f->nametab, node, node);
    return get_ino(node);
}

static char *get_path(fino_t ino)
{
    GString *s;
    char *ss;

    s = g_string_new("");
    if(ino == FUSE_ROOT_INO)
        g_string_prepend_c(s, '/');
    else {
        struct node *node;
        for(; ino != FUSE_ROOT_INO; ino = node->parent) {
            node = get_node(ino);
            g_string_prepend(s, node->name);
            g_string_prepend_c(s, '/');
        }
    }

    ss = s->str;
    g_string_free(s, FALSE);
    
    return ss;
}

static void remove_node(struct fuse *f, fino_t ino)
{
    struct node *node = get_node(ino);
    g_hash_table_remove(f->nametab, node);
    free_node(node);
}


static void convert_stat(struct stat *stbuf, struct fuse_attr *attr)
{
    attr->mode    = stbuf->st_mode;
    attr->nlink   = stbuf->st_nlink;
    attr->uid     = stbuf->st_uid;
    attr->gid     = stbuf->st_gid;
    attr->rdev    = stbuf->st_rdev;
    attr->size    = stbuf->st_size;
    attr->blksize = stbuf->st_blksize;
    attr->blocks  = stbuf->st_blocks;
    attr->atime   = stbuf->st_atime;
    attr->mtime   = stbuf->st_mtime;
    attr->ctime   = stbuf->st_ctime;
}

static int get_attributes(struct fuse *f, fino_t ino, struct fuse_attr *attr)
{
    char *path;
    struct stat buf;
    int res;

    if(f->op.getattr == NULL)
        return -ENOSYS;
    
    path = get_path(ino);
    res = f->op.getattr(path, &buf);
    g_free(path);
    if(res == 0) 
        convert_stat(&buf, attr);
    
    return res;
}

static int read_link(struct fuse *f, fino_t ino, char *buf, size_t size)
{
    char *path;
    int res;
    
    if(f->op.readlink == NULL)
        return -ENOSYS;

    path = get_path(ino);
    res = f->op.readlink(path, buf, size);
    g_free(path);

    return res;
}

static int fill_dir(struct fuse_dh *dh, char *name, int type)
{
    struct fuse_dirent dirent;
    size_t reclen;
    size_t res;

    dirent.ino = find_node(dh->fuse, dh->dir, name, 0);
    dirent.namelen = strlen(name);
    strncpy(dirent.name, name, sizeof(dirent.name));
    dirent.type = type;
    reclen = FUSE_DIRENT_SIZE(&dirent);
    res = fwrite(&dirent, reclen, 1, dh->fp);
    if(res == 0) {
        perror("writing directory file");
        return -EIO;
    }
    return 0;
}

static int get_dir(struct fuse *f, fino_t ino, FILE *fp)
{
    char *path;
    int res;
    struct fuse_dh dh;
    
    if(f->op.getdir == NULL)
        return -ENOSYS;

    dh.fuse = f;
    dh.fp = fp;
    dh.dir = ino;
        
    path = get_path(ino);
    res = f->op.getdir(path, &dh, (dirfiller_t) fill_dir);
    g_free(path);

    return res;
}


static void send_reply(struct fuse *f, struct fuse_in_header *in, int result,
                       void *arg, size_t argsize)
{
    int res;
    char *outbuf;
    size_t outsize;
    struct fuse_out_header *out;

    if(result > 0) {
        fprintf(stderr, "positive result to operation %i : %i\n", in->opcode,
                result);
        result = -ERANGE;
    }

    if(result != 0)
        argsize = 0;

    outsize = sizeof(struct fuse_out_header) + argsize;
    outbuf = (char *) g_malloc(outsize);
    out = (struct fuse_out_header *) outbuf;
    out->unique = in->unique;
    out->result = result;
    if(argsize != 0)
        memcpy(outbuf + sizeof(struct fuse_out_header), arg, argsize);

    printf("   unique: %i, result: %i (%s), outsize: %i\n", out->unique,
           out->result, strerror(-out->result), outsize);
                
    res = write(f->fd, outbuf, outsize);
    if(res == -1)
        perror("writing fuse device");

    g_free(outbuf);
}

static void do_lookup(struct fuse *f, struct fuse_in_header *in, char *name)
{
    int res;
    struct fuse_lookup_out arg;

    arg.ino = find_node(f, in->ino, name, 1);
    res = get_attributes(f, arg.ino, &arg.attr);

    send_reply(f, in, res, &arg, sizeof(arg));
}


static void do_forget(struct fuse *f, unsigned long *inos, size_t num)
{
    size_t i;

    for(i = 0; i < num; i++)
        remove_node(f, inos[i]);
}

static void do_getattr(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    struct fuse_getattr_out arg;

    res = get_attributes(f, in->ino, &arg.attr);
    send_reply(f, in, res, &arg, sizeof(arg));
}

static void do_readlink(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    char link[PATH_MAX + 1];

    res = read_link(f, in->ino, link, PATH_MAX + 1);
    send_reply(f, in, res, link, res == 0 ? strlen(link) : 0);
}

static void do_mknod(struct fuse *f, struct fuse_in_header *in,
                     struct fuse_mknod_in *inarg)
{
    int res;
    struct fuse_mknod_out outarg;
    
    res = -ENOSYS;
    if(f->op.mknod != NULL && f->op.getattr != NULL) {
        char *path;
        struct stat buf;

        outarg.ino = find_node(f, in->ino, inarg->name, 1);
        path = get_path(outarg.ino);
        res = f->op.mknod(path, inarg->mode, inarg->rdev);
        if(res == 0)
            res = f->op.getattr(path, &buf);
        g_free(path);

        if(res == 0)
            convert_stat(&buf, &outarg.attr);
        else
            remove_node(f, outarg.ino);
    }
    send_reply(f, in, res, &outarg, sizeof(outarg));
}

static void do_getdir(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    struct fuse_getdir_out arg;
    FILE *fp = tmpfile();

    res = get_dir(f, in->ino, fp);
    fflush(fp);
    arg.fd = fileno(fp);
    send_reply(f, in, res, &arg, sizeof(arg));
    fclose(fp);
}

void fuse_loop(struct fuse *f)
{
    int res;
    char inbuf[FUSE_MAX_IN];
    struct fuse_in_header *in = (struct fuse_in_header *) inbuf;
    void *inarg = inbuf + sizeof(struct fuse_in_header);
    size_t insize;
    size_t argsize;
    
    while(1) {
        res = read(f->fd, inbuf, sizeof(inbuf));
        if(res == -1) {
            perror("reading fuse device");
            continue;
        }
        insize = res;
        
        if(insize < sizeof(struct fuse_in_header)) {
            fprintf(stderr, "short read on fuse device\n");
            continue;
        }
        printf("unique: %i, opcode: %i, ino: %li, insize: %i (%i)\n",
               in->unique, in->opcode, in->ino, insize, 
               g_hash_table_size(f->nametab));

        argsize = insize - sizeof(struct fuse_in_header);

        switch(in->opcode) {
        case FUSE_LOOKUP:
            do_lookup(f, in, (char *) inarg);
            break;

        case FUSE_FORGET:
            do_forget(f, (unsigned long *) inarg,
                      argsize / sizeof(unsigned long));
            break;

        case FUSE_GETATTR:
            do_getattr(f, in);
            break;

        case FUSE_READLINK:
            do_readlink(f, in);
            break;

        case FUSE_GETDIR:
            do_getdir(f, in);
            break;

        case FUSE_MKNOD:
            do_mknod(f, in, (struct fuse_mknod_in *) inarg);
            break;

        default:
            fprintf(stderr, "Operation %i not implemented\n", in->opcode);
            /* No need to send reply to async requests */
            if(in->unique != 0)
                send_reply(f, in, -ENOSYS, NULL, 0);
        }
    }
}

struct fuse *fuse_new()
{
    struct fuse *f = g_new0(struct fuse, 1);

    f->fd = -1;
    f->dir = NULL;
    f->nametab = g_hash_table_new((GHashFunc) name_hash,
                                  (GCompareFunc) name_compare);

    return f;
}


void fuse_set_operations(struct fuse *f, const struct fuse_operations *op)
{
    f->op = *op;
}

void fuse_destroy(struct fuse *f)
{
    fuse_unmount(f);
    g_hash_table_foreach_remove(f->nametab, (GHRFunc) free_node, NULL);
    g_hash_table_destroy(f->nametab);
    g_free(f);
}
