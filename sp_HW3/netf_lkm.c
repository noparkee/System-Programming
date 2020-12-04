#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>

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

Rule *findRule(List *lst, unsigned short port, char type) {
	Rule *rule;
	for (rule = lst->head; rule != NULL && !(rule->port == port && rule->type == type); rule = rule->next);
	return rule;
}

unsigned int as_addr_to_net(char *str){
	unsigned char arr[4];
	sscanf(str, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);

	return *(unsigned int *)arr;
}

char *as_net_to_addr(unsigned int addr, char str[])
{
	char add[16];
	unsigned char a = ((unsigned char *)&addr)[0];
	unsigned char b = ((unsigned char *)&addr)[1];
	unsigned char c = ((unsigned char *)&addr)[2];
	unsigned char d = ((unsigned char *)&addr)[3];
	sprintf(add, "%u.%u.%u.%u", a, b, c, d);
	sprintf(str, "%s", add);
	
	return str;
}

// return을 통해서 패킷 받을지 말지 결정
	// inbound, outbound log 
	// I - inbound packet drop (close되지 않아도 ㅇㅋ) NF_INET_PRE_ROUTING / NF_INET_LOCAL_IN
	// O - outbound packet drop NF_INET_POST_ROUTING / NF_INET_LOCAL_OUT
	// P - inbound packet's destination -> 131.1.1.1 / port -> source port - NF_INET_PRE_ROUTING
	// F - NF_INET_FORWARD
	// NF_DROP
	// ex) echo "I 1111" > add
	// ex) echo 0 > del : 0 rule delete

static unsigned int netfilter_inbound_hook(void *priv, struct sk_buff *skb,
					const struct nf_hook_state * state){
	// NF_INET_LOCAL_IN
	
	Rule *ptr;
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	char saddr[128], daddr[128];
	unsigned short sport, dport;
	
	as_net_to_addr((unsigned int)(ih->saddr), saddr);
	as_net_to_addr((unsigned int)(ih->daddr), daddr);

	sport = htons(th -> source);
	dport = htons(th -> dest);
	
	ptr = findRule(ruleList, sport, 'I');
	
	if (ptr == NULL){
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s\n", "INBOUND", ih->protocol, sport, dport, saddr, daddr);
		return NF_ACCEPT;

	}
	else{
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s\n", "DROP(INBOUND)", ih->protocol, sport, dport, saddr, daddr);
		return NF_DROP;
		
	}

}

static struct nf_hook_ops netfilter_inbound_ops = {
	.hook = netfilter_inbound_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,	
	.priority = 1,
};

/*---------------------------------------------*/

static unsigned int netfilter_outbound_hook(void *priv, struct sk_buff *skb,
					const struct nf_hook_state * state){
	// NF_INET_LOCAL_OUT
	
	Rule *ptr;
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	char saddr[128], daddr[128];
	unsigned short sport, dport;
	
	as_net_to_addr((unsigned int)(ih->saddr), saddr);
	as_net_to_addr((unsigned int)(ih->daddr), daddr);

	sport = htons(th -> source);
	dport = htons(th -> dest);
	
	ptr = findRule(ruleList, dport, 'O');
	
	if (ptr == NULL){
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s\n", "OUTBOUND", ih->protocol, sport, dport, saddr, daddr);
		return NF_ACCEPT;

	}
	else{
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s\n", "DROP(OUTBOUND)", ih->protocol, sport, dport, saddr, daddr);
		return NF_DROP;
		
	}

}

static struct nf_hook_ops netfilter_outbound_ops = {
	.hook = netfilter_outbound_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,	
	.priority = 1,
};


/* -------------------add---------------------- */
static int add_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "open show\n");
	return 0;
}

static ssize_t add_write(struct file *file, const char __user *user_buffer,
			size_t count, loff_t *ppos){
	printk(KERN_INFO "add write\n");

	int len = 0;
	char buf[BUFSIZE];

	Rule *rule = (Rule*)kmalloc(sizeof(Rule), GFP_KERNEL);
	rule -> next = NULL;

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

	int len = 0;
	int index, i;
	char buf[BUFSIZE];

	Rule *ptr = ruleList -> head;
	Rule *pptr = ruleList -> head;

	if (copy_from_user(buf, user_buffer, count)){
		goto err;	
	}
	
	sscanf(buf, "%d", &index);
	len = strlen(buf);
	
	if (index != 0){
		for (i=0; i<index; i++){
			pptr = ptr;
			ptr = ptr -> next;		
		}	
		if (ptr -> next != NULL){
			pptr -> next = ptr -> next;
			kfree(ptr);
			ruleList -> size--;
		}
		else{
			ruleList -> tail = pptr;
			kfree(ptr);
			ruleList -> size--;
		}
	}
	else if (index == 0){
		ruleList -> head = ptr -> next;
		kfree(ptr);
		ruleList -> size--;
	}
	
	

	return len;
	
	err:
		printk("err!");
		return len;	
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
	int i = 0;

	while (rule != NULL){
		printk("%d(%c) %d\n", i, rule->type, rule->port);
		rule = rule -> next;
		i++;
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

	nf_register_hook(&netfilter_inbound_ops);
	nf_register_hook(&netfilter_outbound_ops);
	
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
	nf_unregister_hook(&netfilter_inbound_ops);
	nf_unregister_hook(&netfilter_outbound_ops);

	// rule free
	// ruleList free
	kfree(ruleList);
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("KU");
MODULE_DESCRIPTION("for sp");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");