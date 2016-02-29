//	CS544
//	Group 36
//	Kai Shi
//	Wen-Yin Wang
//	Xu Zheng
//	Final paper
//	Fuzzing test

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/sysfs.h>
#include <linux/moduleloader.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dirent.h>

#define NUM 5000 
unsigned long **sys_call_table;

int (*getcwd)(char *buf, size_t size);
int (*chdir)(char *path);
int (*open)(char *filename, int flag, int mode);
int (*read)(int fd, char *buf, int size);
int (*lseek)(int fd, off_t offset, int whence);
int (*write)(int fd, char *buf, int size);
int (*close)(int fd);

char fd_addr_db[10][50];
int fd_pm_db[3];
int fd_offset_db[3];	
char alphabet_db[40];

struct fd_info{
	char fd_dir[50];
	char fd_name[50];
	char buff[1024];
	int fd_pm;
	int fd_no;
	int fd_offset;
	int fd_chdir_flag;
	int fd_open_flag;
	int fd_read_flag;
	int fd_lseek_flag;
	int fd_write_flag;
	int fd_close_flag;	
}fd_info_t;

struct fd_info info[NUM];


void fuzzing_test(void);
void info_init(struct fd_info* info);
void fuzz_init(void);
int fuzz(int n);
void fuzz_string(char* s, int n); 
void sys_chdir(struct fd_info* info);
void sys_open(struct fd_info* info);
void sys_read(struct fd_info* info);
void sys_write(struct fd_info* info);
void sys_lseek(struct fd_info* info);
void sys_close(struct fd_info* info);
void info_print(struct fd_info* info);

static unsigned long **find_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;
	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;
		if (sct[__NR_close] == (unsigned long *) sys_close) {
			printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX\n",
			(unsigned long) sct);
			return sct;
		}
	offset += sizeof(void *);
	}
	return NULL;
}

static int __init fuzzer_init(void)
{
	printk(KERN_ALERT "Testing fuzz.\n");
	sys_call_table = find_sys_call_table();	//find system call table 	
	fuzz_init();	//initial data
	fuzzing_test(); //do fuzzing test	
	return 0;
}

static void __exit fuzzer_exit(void)
{
	printk(KERN_ALERT "End fuzz.\n");
}

void fuzzing_test(void)
{
	int i;
	for(i = 0; i < NUM; i++){
		info_init(&info[i]);
		sys_chdir(&info[i]);
		sys_open(&info[i]);
		sys_read(&info[i]);
		sys_lseek(&info[i]);
		sys_write(&info[i]);
		sys_close(&info[i]);
		info_print(&info[i]);
	}
}

void info_init(struct fd_info* info)
{
	sprintf(info -> fd_name, " ");
	info -> fd_pm = fd_pm_db[fuzz(3)];
	info -> fd_no = 0;
	info -> fd_offset = fd_offset_db[fuzz(3)];
	info -> fd_chdir_flag = 0;
	info -> fd_open_flag = 0;
	info -> fd_read_flag = 0;
	info -> fd_lseek_flag = 0;
	info -> fd_write_flag = 0;
	info -> fd_close_flag = 0;
}

void fuzz_init(void)
{
	fd_pm_db[0] = O_RDWR;
	fd_pm_db[1] = O_RDONLY;
	fd_pm_db[2] = O_WRONLY;
	fd_offset_db[0] = SEEK_SET;
	fd_offset_db[1] = SEEK_CUR;
	fd_offset_db[2] = SEEK_END;
	sprintf(alphabet_db, "_-.0123456789abcdefghijklmnopqrstuvwxyz/");
}

int fuzz(int n)
{
	int i;
	get_random_bytes(&i, 1);
	if(i < 0){
		abs(i);
	}
	return i % n;
}

void fuzz_string(char* s, int n)
{
	int i;
	char new_s[n];
	for(i = 0; i < n; i++){
		new_s[i] = alphabet_db[fuzz(40)];
	}
	sprintf(s, "%s", new_s);
} 

void sys_chdir (struct fd_info* info)
{
	//test chdir
	//results: Success: 1, Fail: 0, Except: -1
	int i;
	char cwd[100] = {'\0'};
	char new_dir[20] = {'\0'};
	chdir = (void *)sys_call_table[__NR_chdir];
	getcwd = (void *)sys_call_table[__NR_getcwd];
	getcwd(cwd, sizeof(cwd));
	fuzz_string(new_dir, 20);
	sprintf(info -> fd_dir, "%s", new_dir);
	if((i = chdir(new_dir)) == -1){
		info -> fd_chdir_flag = 0;
	}
	else if(i == 0){
		info -> fd_chdir_flag = 1;
	}
	else{
		info -> fd_chdir_flag = -1;
	}	
	printk(KERN_ALERT "random pathname: %s, chdir_flag: %d\n", info -> fd_dir, info -> fd_chdir_flag);
}

void sys_open(struct fd_info* info)
{
	//test open
	//results: Success: 1, Fail: 0, Except: -1
	char new_name[10] = {'\0'};
	open = (void *)sys_call_table[__NR_open];
	fuzz_string(new_name, 10);
	sprintf(info -> fd_name, "%s", new_name);
	if((info -> fd_no = open(info -> fd_name, info -> fd_pm, 0644)) == -1){
		info -> fd_open_flag = 0;
	}
	else if(info -> fd_no >= 0){
		info -> fd_open_flag = 1;
	}
	else{
		info -> fd_open_flag = -1;
	}
	printk(KERN_ALERT "random filename: %s, open_flag: %d\n", info -> fd_name, info -> fd_open_flag);
}

void sys_read(struct fd_info* info)
{
	//test read
	//results: Success: 1, Fail: 0, Except: -1
	int i;
	read = (void *)sys_call_table[__NR_read];
	if((i = read(info -> fd_no, info -> buff, sizeof(info -> buff))) == -1){
		info -> fd_read_flag = 0;
	}
	else if(i >= 0){
		info -> fd_read_flag = 1;
	}
	else{
		info -> fd_read_flag = -1;
	}
	printk(KERN_ALERT "file number: %d, read_flag: %d\n", info -> fd_no, info -> fd_read_flag);
}

void sys_lseek (struct fd_info* info)
{
	//test lseek
	//results: Success: 1, Fail: 0, Except: -1	
	int i;
	lseek = (void *)sys_call_table[__NR_lseek];
	if((i = lseek(info -> fd_no, 0, info -> fd_offset)) == -1){
		info -> fd_lseek_flag = 0;
	}
	else if(i >= 0){
		info -> fd_lseek_flag = 1;
	}
	else{
		info -> fd_lseek_flag = -1;
	}
	printk(KERN_ALERT "file number: %d, lseek_flag: %d\n", info -> fd_no, info -> fd_lseek_flag);
}

void sys_write(struct fd_info* info)
{
	//test write
	//results: Success: 1, Fail: 0, Except: -1
	int i;	
	write = (void *)sys_call_table[__NR_write];
	if((i = write(info -> fd_no, info -> buff, strlen(info -> buff))) == -1){
		info -> fd_write_flag = 0;
	}
	else if(i >= 0){
		info -> fd_write_flag = 1;
	}
	else{
		info -> fd_write_flag = -1;
	}
	printk(KERN_ALERT "file number: %d, write_flag: %d\n", info -> fd_no, info -> fd_write_flag);
}

void sys_close(struct fd_info* info)
{
	//test close()
	//results: Success: 1, Fail: 0, Except: -1
	int i;	
	close = (void *)sys_call_table[__NR_close];
	if((i = close(info -> fd_no)) == -1){
		info -> fd_close_flag = 0;
	}
	else if(i == 0){
		info -> fd_close_flag = 1;
	}
	else{
		info -> fd_close_flag = -1;
	}
	printk(KERN_ALERT "file number: %d, close_flag: %d\n", info -> fd_no, info -> fd_close_flag);
}

void info_print (struct fd_info* info)
{
	printk(KERN_ALERT "\nFile information:\n");
	printk(KERN_ALERT "\tFile dir: %s\n\tFile name: %s\n\tFile permission: %d\n\tFile descriptor no: %d\n\tFile offset: %d\n", info -> fd_dir, info -> fd_name, info -> fd_pm, info -> fd_no, info -> fd_offset);
	printk(KERN_ALERT "\tFile chdir flag: %d\n\tFile open flag: %d\n\tFile read flag: %d\n\tFile sleek flag: %d\n\tFile write flag: %d\n\tFile close flag: %d\n", info -> fd_chdir_flag, info -> fd_open_flag, info -> fd_read_flag, info -> fd_lseek_flag, info -> fd_write_flag, info -> fd_close_flag);
	printk(KERN_ALERT "End file.\n");
}

module_init(fuzzer_init);
module_exit(fuzzer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group 36");
MODULE_DESCRIPTION("FUZZER MODULE");