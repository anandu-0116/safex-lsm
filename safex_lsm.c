#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include "include/safex.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anandapadmanabhan");
MODULE_DESCRIPTION("Safex - Read Access Control LSM");

// Linked list of denied entries
struct deny_entry {
    char path[MAX_PATH_LEN];
    struct list_head list;
};

static LIST_HEAD(denylist);

static DEFINE_MUTEX(denylist_mutex);
static bool denylist_loaded = false;
static bool lsm_active = false;
static struct delayed_work activation_work;
static int load_attempts = 0;

// ------------------------------
// Deny Logic
// ------------------------------

bool is_path_denied(const char *path) {
    struct deny_entry *entry;

    // If LSM is not active, don't check
    if (!lsm_active) {
        return false;
    }

    printk(KERN_INFO "safex: Comparing against denylist for %s\n", path);
    list_for_each_entry(entry, &denylist, list) {
        printk(KERN_INFO "safex: comparing with %s\n", entry->path);
        if(strcmp(entry->path, path) == 0) {
            printk(KERN_INFO "safex: Matched path %s\n", path);
            return true;
        }
    }
    return false;
}

int load_denylist(void) {
    struct file *file;
    char buf[MAX_PATH_LEN];
    loff_t pos = 0;
    ssize_t read_ret;
    int len = 0;

    printk(KERN_INFO "safex: Using denylist path: %s\n", DENYLIST_PATH);

    file = filp_open(DENYLIST_PATH, O_RDONLY, 0);
    if(IS_ERR(file)) {
        printk(KERN_ERR "safex: Could not open denylist at %s\n", DENYLIST_PATH);
        return PTR_ERR(file);
    }

    while((read_ret = kernel_read(file, buf + len, 1, &pos)) == 1) {
        if(buf[len] == '\n' || len == MAX_PATH_LEN - 1) {
            buf[len] = '\0';
            if(len > 0) {
                struct deny_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                if(!entry) continue;
                strncpy(entry->path, buf, MAX_PATH_LEN);
                list_add_tail(&entry->list, &denylist);
            }
            len = 0;
        } else {
            len++;
        }
    }

    filp_close(file, NULL);
    printk(KERN_INFO "safex: Loaded denylist from %s\n", DENYLIST_PATH);
    return 0;
}

void cleanup_denylist(void) {
    struct deny_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &denylist, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

static void activate_lsm_work(struct work_struct *work) {
    mutex_lock(&denylist_mutex);
    
    if (!denylist_loaded && load_attempts < MAX_LOAD_ATTEMPTS) {
        load_attempts++;
        printk(KERN_INFO "safex: Load attempt %d/%d\n", load_attempts, MAX_LOAD_ATTEMPTS);
        
        int ret = load_denylist();
        if (ret == 0) {
            denylist_loaded = true;
            lsm_active = true;
            printk(KERN_INFO "safex: LSM now active with denylist loaded after %d attempts\n", load_attempts);
        } else {
            printk(KERN_WARNING "safex: Load attempt %d failed (ret=%d)\n", load_attempts, ret);
            
            if (load_attempts < MAX_LOAD_ATTEMPTS) {
                // Schedule another attempt in 10 seconds
                printk(KERN_INFO "safex: Scheduling retry in 10 seconds\n");
                schedule_delayed_work(&activation_work, 10 * HZ);
            } else {
                printk(KERN_WARNING "safex: Maximum load attempts reached, LSM remaining inactive\n");
            }
        }
    }
    
    mutex_unlock(&denylist_mutex);
}

// ------------------------------
// LSM Hook
// ------------------------------

static int safex_file_open(struct file *file) {
    // Skip if LSM not active yet
    if (!lsm_active) {
        return 0;
    }

    printk(KERN_INFO "safex: safex_file_open() called!\n");
    char *tmp;
    char *path;

    tmp = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp)
        return 0;

    path = dentry_path_raw(file->f_path.dentry, tmp, PAGE_SIZE);
    if(!IS_ERR(path)) {
        printk(KERN_INFO "safex: checking file path: %s\n", path);
        if(is_path_denied(path)) {
            printk(KERN_INFO "safex: Blocking read access to %s\n", path);
            free_page((unsigned long)tmp);
            return -EACCES;
        }
    }

    free_page((unsigned long)tmp);
    return 0;
}

// ------------------------------
// Module Init/Exit
// ------------------------------

static struct security_hook_list safex_hooks[] = {
    LSM_HOOK_INIT(file_open, safex_file_open),
};

static struct lsm_id safex_lsmid = {
    .name = "safex",
};

static int __init safex_lsm_init(void) {
    printk(KERN_INFO "safex: Inside safex_lsm_init!\n");

    // Schedule LSM activation for later
    INIT_DELAYED_WORK(&activation_work, activate_lsm_work);
    schedule_delayed_work(&activation_work, 10 * HZ);

    security_add_hooks(safex_hooks, ARRAY_SIZE(safex_hooks), &safex_lsmid);

    printk(KERN_INFO "safex: LSM initialized.\n");
    return 0;
}

DEFINE_LSM(safex) = {
    .name = "safex",
    .init = safex_lsm_init,
};