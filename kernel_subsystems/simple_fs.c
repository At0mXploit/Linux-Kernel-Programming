/*
 * simple_fs.c - Minimal in-memory filesystem demonstration
 *
 * Demonstrates VFS concepts by implementing a minimal
 * RAM-backed filesystem that can be registered, mounted, and used.
 *
 * This filesystem supports:
 *   - Creating and reading regular files
 *   - Creating directories
 *   - Basic read/write operations using page cache
 *
 * Usage:
 *   insmod simple_fs.ko
 *   mkdir /mnt/simplefs
 *   mount -t simplefs none /mnt/simplefs
 *   echo "hello" > /mnt/simplefs/test
 *   cat /mnt/simplefs/test
 *   umount /mnt/simplefs
 *   rmmod simple_fs
 *
 * Build: Part of the kernel_subsystems Makefile
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>

#define SIMPLEFS_MAGIC      0x53464D50  /* "SFMP" */
#define SIMPLEFS_BLOCKSIZE  PAGE_SIZE
#define SIMPLEFS_MAX_FILESIZE (PAGE_SIZE * 256)  /* 1MB max file size */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Subsystems Lab");
MODULE_DESCRIPTION("Minimal in-memory filesystem for VFS study");

/* ──────────────── Forward declarations ──────────────── */

static const struct inode_operations simplefs_dir_inode_ops;
static const struct inode_operations simplefs_file_inode_ops;
static const struct file_operations simplefs_dir_ops;
static const struct file_operations simplefs_file_ops;
static const struct super_operations simplefs_super_ops;
static const struct address_space_operations simplefs_aops;

/* ──────────────── Inode creation ──────────────── */

/*
 * simplefs_make_inode - Create a new inode for the filesystem
 * @sb:   superblock this inode belongs to
 * @dir:  parent directory inode (NULL for root)
 * @mode: file mode (type + permissions)
 *
 * This function demonstrates how a filesystem creates inodes.
 * In a real filesystem, the inode number and metadata would come
 * from on-disk structures. Here we generate them dynamically.
 */
static struct inode *simplefs_make_inode(struct super_block *sb,
                                         const struct inode *dir,
                                         umode_t mode)
{
    struct inode *inode;

    inode = new_inode(sb);
    if (!inode)
        return NULL;

    /* Set basic inode fields */
    inode->i_ino = get_next_ino();       /* unique inode number           */
    inode->i_mode = mode;                /* file type + permissions       */
    inode->i_uid = current_fsuid();      /* owner = current user          */
    inode->i_gid = current_fsgid();      /* group = current group         */
    inode->i_blocks = 0;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

    /* Set operations based on file type */
    switch (mode & S_IFMT) {
    case S_IFDIR:
        /* Directory: needs directory inode ops and file ops */
        inode->i_op = &simplefs_dir_inode_ops;
        inode->i_fop = &simplefs_dir_ops;
        /*
         * Directory link count starts at 2:
         * one for "." and one for the parent's reference
         */
        set_nlink(inode, 2);
        break;

    case S_IFREG:
        /* Regular file: needs file inode ops, file ops, and aops */
        inode->i_op = &simplefs_file_inode_ops;
        inode->i_fop = &simplefs_file_ops;
        inode->i_mapping->a_ops = &simplefs_aops;
        break;

    default:
        pr_warn("simplefs: unsupported file type 0%o\n", mode & S_IFMT);
        iput(inode);
        return NULL;
    }

    return inode;
}

/* ──────────────── Directory operations ──────────────── */

/*
 * simplefs_create - Create a new file in a directory
 *
 * Called by the VFS when a process calls open() with O_CREAT.
 * We create a new inode and link it into the directory via
 * the dentry.
 */
static int simplefs_create(struct mnt_idmap *idmap,
                            struct inode *dir, struct dentry *dentry,
                            umode_t mode, bool excl)
{
    struct inode *inode;

    inode = simplefs_make_inode(dir->i_sb, dir, mode | S_IFREG);
    if (!inode)
        return -ENOMEM;

    /*
     * d_instantiate: associate the new inode with the dentry.
     * After this, the VFS knows that dentry->d_name maps to this inode.
     */
    d_instantiate(dentry, inode);

    /*
     * dget: take an extra reference on the dentry.
     * This keeps the dentry cached even when no process has the file open.
     */
    dget(dentry);

    /* Update parent directory timestamps */
    dir->i_mtime = dir->i_ctime = current_time(dir);

    pr_info("simplefs: created file '%s' (ino=%lu)\n",
            dentry->d_name.name, inode->i_ino);
    return 0;
}

/*
 * simplefs_mkdir - Create a new directory
 *
 * Similar to create, but for directories. We also need to
 * increment the parent's link count (for the ".." entry).
 */
static int simplefs_mkdir(struct mnt_idmap *idmap,
                           struct inode *dir, struct dentry *dentry,
                           umode_t mode)
{
    struct inode *inode;

    inode = simplefs_make_inode(dir->i_sb, dir, mode | S_IFDIR);
    if (!inode)
        return -ENOMEM;

    d_instantiate(dentry, inode);
    dget(dentry);

    /* Parent gains a link for the ".." entry in the new directory */
    inc_nlink(dir);
    dir->i_mtime = dir->i_ctime = current_time(dir);

    pr_info("simplefs: created directory '%s' (ino=%lu)\n",
            dentry->d_name.name, inode->i_ino);
    return 0;
}

/*
 * simplefs_lookup - Look up a name in a directory
 *
 * Called during path resolution. For an in-memory filesystem,
 * all dentries are already in the dcache, so we just return
 * NULL (which tells the VFS "not found" as a negative dentry).
 *
 * A real filesystem would search its on-disk directory structures here.
 */
static struct dentry *simplefs_lookup(struct inode *dir,
                                       struct dentry *dentry,
                                       unsigned int flags)
{
    /* For ramfs-like filesystems, dcache handles everything */
    return simple_lookup(dir, dentry, flags);
}

/* ──────────────── Address space operations (page cache) ──────────────── */

/*
 * These operations allow the page cache to manage our file data.
 * simple_readpage and simple_write_begin/end are kernel helpers
 * that work perfectly for in-memory filesystems.
 */
static const struct address_space_operations simplefs_aops = {
    .readpage       = simple_readpage,
    .write_begin    = simple_write_begin,
    .write_end      = simple_write_end,
    .dirty_folio    = noop_dirty_folio,
};

/*
 * simplefs_setattr - Handle attribute changes (chmod, chown, truncate)
 *
 * We delegate to simple_setattr which handles the common cases.
 */
static int simplefs_setattr(struct mnt_idmap *idmap,
                             struct dentry *dentry, struct iattr *iattr)
{
    struct inode *inode = d_inode(dentry);
    int error;

    error = setattr_prepare(idmap, dentry, iattr);
    if (error)
        return error;

    /* Handle truncation: adjust page cache */
    if (iattr->ia_valid & ATTR_SIZE)
        truncate_setsize(inode, iattr->ia_size);

    setattr_copy(idmap, inode, iattr);
    mark_inode_dirty(inode);
    return 0;
}

/* ──────────────── Operations tables ──────────────── */

static const struct inode_operations simplefs_dir_inode_ops = {
    .lookup     = simplefs_lookup,
    .create     = simplefs_create,
    .mkdir      = simplefs_mkdir,
    .setattr    = simplefs_setattr,
};

static const struct inode_operations simplefs_file_inode_ops = {
    .setattr    = simplefs_setattr,
    .getattr    = simple_getattr,
};

static const struct file_operations simplefs_dir_ops = {
    .open       = dcache_dir_open,
    .release    = dcache_dir_close,
    .llseek     = dcache_dir_lseek,
    .read       = generic_read_dir,
    .iterate_shared = dcache_readdir,
};

static const struct file_operations simplefs_file_ops = {
    .read_iter  = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .mmap       = generic_file_mmap,
    .fsync      = noop_fsync,
    .llseek     = generic_file_llseek,
};

/* ──────────────── Superblock operations ──────────────── */

static int simplefs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    buf->f_type = SIMPLEFS_MAGIC;
    buf->f_bsize = SIMPLEFS_BLOCKSIZE;
    buf->f_namelen = NAME_MAX;
    return 0;
}

static const struct super_operations simplefs_super_ops = {
    .statfs         = simplefs_statfs,
    .drop_inode     = generic_delete_inode,
};

/* ──────────────── Superblock fill (mount) ──────────────── */

/*
 * simplefs_fill_super - Initialize the superblock on mount
 *
 * This is called when the filesystem is mounted. We set up the
 * superblock parameters and create the root inode/dentry.
 */
static int simplefs_fill_super(struct super_block *sb, void *data,
                                int silent)
{
    struct inode *root_inode;

    /* Configure superblock */
    sb->s_blocksize = SIMPLEFS_BLOCKSIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = SIMPLEFS_MAGIC;
    sb->s_op = &simplefs_super_ops;
    sb->s_maxbytes = SIMPLEFS_MAX_FILESIZE;
    sb->s_time_gran = 1;  /* nanosecond timestamp granularity */

    /* Create root inode (directory, mode 0755) */
    root_inode = simplefs_make_inode(sb, NULL, S_IFDIR | 0755);
    if (!root_inode) {
        pr_err("simplefs: failed to create root inode\n");
        return -ENOMEM;
    }

    /*
     * d_make_root: create the root dentry and associate it
     * with the root inode. This also sets sb->s_root.
     */
    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        pr_err("simplefs: failed to create root dentry\n");
        /* d_make_root calls iput on failure */
        return -ENOMEM;
    }

    pr_info("simplefs: mounted successfully (magic=0x%lX)\n",
            (unsigned long)sb->s_magic);
    return 0;
}

/* ──────────────── Mount and unmount ──────────────── */

/*
 * simplefs_mount - Mount callback
 *
 * mount_nodev is used because we have no backing block device.
 * This is appropriate for RAM-based filesystems.
 */
static struct dentry *simplefs_mount(struct file_system_type *fs_type,
                                      int flags, const char *dev_name,
                                      void *data)
{
    return mount_nodev(fs_type, flags, data, simplefs_fill_super);
}

static void simplefs_kill_sb(struct super_block *sb)
{
    pr_info("simplefs: unmounting\n");
    kill_litter_super(sb);
}

/* ──────────────── Filesystem type registration ──────────────── */

/*
 * This structure tells the VFS about our filesystem.
 * After register_filesystem(), it appears in /proc/filesystems
 * and can be used with the mount command.
 */
static struct file_system_type simplefs_type = {
    .owner      = THIS_MODULE,
    .name       = "simplefs",
    .mount      = simplefs_mount,
    .kill_sb    = simplefs_kill_sb,
    .fs_flags   = FS_USERNS_MOUNT,  /* Allow mounting in user namespaces */
};

static int __init simplefs_init(void)
{
    int ret;

    ret = register_filesystem(&simplefs_type);
    if (ret) {
        pr_err("simplefs: failed to register filesystem: %d\n", ret);
        return ret;
    }

    pr_info("simplefs: filesystem registered\n");
    pr_info("simplefs: mount with: mount -t simplefs none <mountpoint>\n");
    return 0;
}

static void __exit simplefs_exit(void)
{
    unregister_filesystem(&simplefs_type);
    pr_info("simplefs: filesystem unregistered\n");
}

module_init(simplefs_init);
module_exit(simplefs_exit);
