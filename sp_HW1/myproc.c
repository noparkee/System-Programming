#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROC_DIRNAME "ext4_dir"
#define PROC_FILENAME "ext4_file"
#define QSIZE 100

typedef struct {   // 구조체 정의
    const char *fs_name;        
    unsigned int block_number;     
    long time;
} BlockQueue;

extern BlockQueue bqueue[QSIZE];
int idx = 0;


static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

static int my_open(struct inode *inode, struct file *file){
	printk("OPEN!\n");
	return 0;
}

static ssize_t my_read(struct file * file, char __user *buf, size_t count, loff_t * ofs)
{	
	BlockQueue block = bqueue[idx];
	int len  = sprintf(buf, "index: %d || time: %ld || fs_name: %s || block_number: %u \n", idx, block.time, block.fs_name, block.block_number);
	printk("block_number: %u\n", block.block_number);
	idx ++;
	printk("%d\n", idx);
    if (idx == QSIZE + 1){
	idx = 0;        
	return 0;
	}
    else
         return len;
}


static const struct file_operations myproc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read,
};

static int my_init(void){
	printk(KERN_ALERT "init\n");
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file = proc_create(PROC_FILENAME, 0777, proc_dir, &myproc_fops);
	return 0;
}

static void my_exit(void){
	remove_proc_entry(PROC_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);


	printk(KERN_ALERT "exit\n");
	return;
}

module_init(my_init);
module_exit(my_exit);

MODULE_AUTHOR("CHANO");
MODULE_DESCRIPTION("FOR SP");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
