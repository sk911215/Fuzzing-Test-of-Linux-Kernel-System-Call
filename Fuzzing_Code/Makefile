#Kai Shi, Wen-yin Wang, Xu Zheng
#CS544-001 
#Group 36

obj-m := fuzzing.o
KERNELDIR = /scratch/spring2015/cs444-group36/linux-yocto-3.14_1/

all:
	make -C $(KERNELDIR) M=$(PWD) modules
	rm -f *~

clean:
	make -C $(KERNELDIR) M=$(PWD) clean