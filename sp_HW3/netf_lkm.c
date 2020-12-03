#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>

#define PROC_DIRNAME "customfilrewall"
#define PROC_ADD "add"
#define PROC_DEL "del"
#define PROC_SHOW "show"

#define BUFSIZE 64

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_add;
static struct proc_dir_entry *proc_del;
static struct proc_dir_entry *proc_show;

typedef struct list{
	struct rule *head;
	struct rule *tail;
	int size;	
} List;

typedef struct rule{
	struct rule *next;
	int port;
	char type;
} Rule;


static List *ruleList;


static unsigned int netfilter_hook_fn(void *priv, struct sk_buff *skb,
					const struct nf_hook_state * state){
	
	// return을 통해서 패킷 받을지 말지 결정
	// inbound, outbound log 
	// I - inbound packet drop (close되지 않아도 ㅇㅋ)
	// O - outbound packet drop  
	// P -
	// F -

	// ex) echo "I 1111" > add
	// ex) echo 0 > del : 0 rule delete
}

static struct nf_hook_ops netfilter_ops = {
	.hook = netfilter_hook_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = 1,
};


/* -------------------add---------------------- */
static int add_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "open show\n");
	return 0;
}

static ssize_t add_write(struct file *file, const char __user *user_buffer,
			size_t count, loff_t *ppos){
	int len = 0;
	char buf[BUFSIZE];

	Rule *rule = (Rule*)kmalloc(sizeof(Rule), GFP_KERNEL);
	rule -> next = NULL;

	printk(KERN_INFO "add write\n");

	if (copy_from_user(buf, user_buffer, count)){
		goto err;	
	}
	
	sscanf(buf, "%c %d", &(rule -> type), &(rule -> port));
	len = strlen(buf);

	if (ruleList -> size == 0)
		ruleList -> head = rule;
	else
		ruleList -> tail -> next = rule;
	
	ruleList -> tail = rule;
	ruleList -> size++;
	
	return len;
	
	err:
		printk("err!");
		return len;
}

static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = add_open,
	.write = add_write,
};


/* -------------------del---------------------- */
static int del_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "open show\n");
	return 0;
}

static ssize_t del_write(struct file *file, const char __user *user_buffer,
			size_t count, loff_t *ppos){
	printk(KERN_INFO "del write\n");
	
	return count;
}

static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = del_open,
	.write = del_write,
};


/* -------------------show---------------------- */
static int show_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "open show\n");
	return 0;
}

static ssize_t show_read(struct file *file, char __user *user_buffer,
			size_t size, loff_t *ppos){
	printk(KERN_INFO "read show\n");
	Rule *rule = ruleList -> head;
	while (rule != NULL){
		printk("%c %d\n", rule->type, rule->port);
		rule = rule -> next;
	}
	return 0;
}

static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = show_open,
	.read = show_read,
};



static int __init init(void){
	printk(KERN_INFO "module INIT!\n");
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_add = proc_create(PROC_ADD, 0777, proc_dir, &add_fops);
	proc_del = proc_create(PROC_DEL, 0777, proc_dir, &del_fops);		 	
	proc_show = proc_create(PROC_SHOW, 0777, proc_dir, &show_fops);

	nf_register_hook(&netfilter_ops);
	
	ruleList = (List*)kmalloc(sizeof(List), GFP_KERNEL);
	ruleList -> head = NULL;
	ruleList -> tail = NULL;
	ruleList -> size = 0;

	return 0;
}

static void __exit exit(void){
	printk(KERN_INFO "module EXIT\n");

	remove_proc_entry(PROC_ADD, proc_dir);
	remove_proc_entry(PROC_DEL, proc_dir);
	remove_proc_entry(PROC_SHOW, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);
	nf_unregister_hook(&netfilter_ops);
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("KU");
MODULE_DESCRIPTION("for sp");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");