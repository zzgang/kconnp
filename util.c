#include "local_func.h"
#include "util.h"

#define sysctl_nr_open 1024 * 1024

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
static inline unsigned long task_rlimit(const struct task_struct *tsk,
        unsigned int limit)
{
    return tsk->signal->rlim[limit].rlim_cur;
}
#endif

static inline void lkm_free_fdtable(FILE_FDT_TYPE *fdt)
{
    call_rcu(&fdt->rcu, local_free_fdtable_rcu);
}

static inline void * lkm_alloc_fdmem(unsigned int size)
{
    if (size <= PAGE_SIZE)
        return kmalloc(size, GFP_KERNEL);
    else
        return vmalloc(size);
}

static inline void lkm_free_fdarr(struct fdtable *fdt)
{
    if (fdt->max_fds <= (PAGE_SIZE / sizeof(struct file *)))
        kfree(fdt->fd);
    else
        vfree(fdt->fd);
}

static inline void lkm_free_fdset(struct fdtable *fdt)
{
    if (fdt->max_fds <= (PAGE_SIZE * BITS_PER_BYTE / 2))
        kfree(fdt->open_fds);
    else
        vfree(fdt->open_fds);
}

/*
 * Expand the fdset in the files_struct.  Called with the files spinlock
 * held for write.
 */
static void lkm_copy_fdtable(FILE_FDT_TYPE *nfdt, FILE_FDT_TYPE *ofdt)
{
    unsigned int cpy, set;

    BUG_ON(nfdt->max_fds < ofdt->max_fds);

    cpy = ofdt->max_fds * sizeof(struct file *);
    set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
    memcpy(nfdt->fd, ofdt->fd, cpy);
    memset((char *)(nfdt->fd) + cpy, 0, set);

    cpy = ofdt->max_fds / BITS_PER_BYTE;
    set = (nfdt->max_fds - ofdt->max_fds) / BITS_PER_BYTE;
    memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
    memset((char *)(nfdt->open_fds) + cpy, 0, set);
    memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
    memset((char *)(nfdt->close_on_exec) + cpy, 0, set);
}

static FILE_FDT_TYPE *lkm_alloc_fdtable(unsigned int nr)
{
    FILE_FDT_TYPE *fdt;
    char *data;

    /*
     * Figure out how many fds we actually want to support in this fdtable.
     * Allocation steps are keyed to the size of the fdarray, since it
     * grows far faster than any of the other dynamic data. We try to fit
     * the fdarray into comfortable page-tuned chunks: starting at 1024B
     * and growing in powers of two from there on.
     */
    nr /= (1024 / sizeof(struct file *));
    nr = roundup_pow_of_two(nr + 1);
    nr *= (1024 / sizeof(struct file *));
    /*
     * Note that this can drive nr *below* what we had passed if sysctl_nr_open
     * had been set lower between the check in expand_files() and here.  Deal
     * with that in caller, it's cheaper that way.
     *
     * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
     * bitmaps handling below becomes unpleasant, to put it mildly...
     */
    if (unlikely(nr > sysctl_nr_open))
        nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

    fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL);
    if (!fdt)
        goto out;
    fdt->max_fds = nr;
    data = lkm_alloc_fdmem(nr * sizeof(struct file *));
    if (!data)
        goto out_fdt;
    fdt->fd = (struct file **)data;
    data = lkm_alloc_fdmem(max_t(unsigned int,
                2 * nr / BITS_PER_BYTE, L1_CACHE_BYTES));
    if (!data)
        goto out_arr;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    fdt->open_fds = (fd_set *)data;
#else
    fdt->open_fds = data;
#endif
    data += nr / BITS_PER_BYTE;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    fdt->close_on_exec = (fd_set *)data;
#else
    fdt->close_on_exec = data;
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 36) 
    INIT_RCU_HEAD(&fdt->rcu);
#endif

    fdt->next = NULL;

    return fdt;
out_arr:
    lkm_free_fdarr(fdt);
out_fdt:
    kfree(fdt);
out:
    return NULL;
}

/*
 * Expand the file descriptor table.
 * This function will allocate a new fdtable and both fd array and fdset, of
 * the given size.
 * Return <0 error code on error; 1 on successful completion.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int task_expand_fdtable(struct task_struct *tsk,
        struct files_struct *files, int nr)
    __releases(files->file_lock)
__acquires(files->file_lock)
{
    struct fdtable *new_fdt, *cur_fdt;

    spin_unlock(&files->file_lock);
    new_fdt = lkm_alloc_fdtable(nr);
    spin_lock(&files->file_lock);
    if (!new_fdt)
        return -ENOMEM;
    /*
     * extremely unlikely race - sysctl_nr_open decreased between the check in
     * caller and alloc_fdtable().  Cheaper to catch it here...
     */
    if (unlikely(new_fdt->max_fds <= nr)) {
        lkm_free_fdarr(new_fdt);
        lkm_free_fdset(new_fdt);
        kfree(new_fdt);
        return -EMFILE;
    }
    /*
     * Check again since another task may have expanded the fd table while
     * we dropped the lock
     */
    cur_fdt = TASK_FILES_FDT(tsk);
    if (nr >= cur_fdt->max_fds) {
        /* Continue as planned */
        lkm_copy_fdtable(new_fdt, cur_fdt);
        rcu_assign_pointer(files->fdt, new_fdt);
        if (cur_fdt->max_fds > NR_OPEN_DEFAULT)
            lkm_free_fdtable(cur_fdt);
    } else {
        /* Somebody else expanded, so undo our attempt */
        lkm_free_fdarr(new_fdt);
        lkm_free_fdset(new_fdt);
        kfree(new_fdt);
    }
    return 1;
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
int task_expand_files(struct task_struct *tsk, struct files_struct *files, int nr)
{
    FILE_FDT_TYPE *fdt;

    fdt = TASK_FILES_FDT(tsk);

    /*
     * N.B. For clone tasks sharing a files structure, this test
     * will limit the total number of files that can be opened.
     */
    if (nr >= task_rlimit(tsk, RLIMIT_NOFILE))
        return -EMFILE;

    /* Do we need to expand? */
    if (nr < fdt->max_fds)
        return 0;
    /* Can we expand? */
    if (nr >= sysctl_nr_open)
        return -EMFILE;

    /* All good, so we try */
    return task_expand_fdtable(tsk, files, nr);
}

/*
 *allocate a file descriptor, mark it busy.
 */
int task_alloc_fd(struct task_struct *tsk, unsigned start, unsigned flags)
{
    struct files_struct *files = tsk->files;
    unsigned int fd;
    int error;
    FILE_FDT_TYPE *fdt;

    spin_lock(&files->file_lock);
repeat:
    fdt = TASK_FILES_FDT(tsk);
    fd = start;
    if (fd < files->next_fd)
        fd = files->next_fd;

    if (fd < fdt->max_fds)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
        fd = find_next_zero_bit(fdt->open_fds->fds_bits,
                fdt->max_fds, fd);
#else
        fd = find_next_zero_bit(fdt->open_fds, fdt->max_fds, fd);
#endif

    error = task_expand_files(tsk, files, fd);
    if (error < 0)
        goto out;

    /*
     * If we needed to expand the fs array we
     * might have blocked - try again.
     */
    if (error)
        goto repeat;

    if (start <= files->next_fd)
        files->next_fd = fd + 1;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    FD_SET(fd, fdt->open_fds);
#else
    __set_open_fd(fd, fdt);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    if (flags & O_CLOEXEC)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
        FD_SET(fd, fdt->close_on_exec);
#else
         __set_close_on_exec(fd, fdt);
#endif
    else
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
        FD_CLR(fd, fdt->close_on_exec);
#else
        __clear_close_on_exec(fd, fdt); 
#endif

    error = fd;

#if 1
    /* sanity check */
    if (rcu_dereference(fdt->fd[fd]) != NULL) {
        printk(KERN_WARNING "alloc_fd: slot %d not null!\n", fd);
        rcu_assign_pointer(fdt->fd[fd], NULL);
    }
#endif

out:
    spin_unlock(&files->file_lock);
    return error;
}
