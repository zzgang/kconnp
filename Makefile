obj-m = kconnp.o
kconnp-objs := connp_entry.o sys_call.o sockp.o connp.o preconnect.o connpd.o sys_socketcalls.o sys_close.o sys_exit.o sys_exit_group.o sys_io.o hash.o cfg.o lkm_util.o

export CONFIG_FRAME_POINTER=ON

all:
	make -C /lib/modules/4.2.1/build SUBDIRS=$(PWD) modules
clean:
	make -C /lib/modules/4.2.1/build SUBDIRS=$(PWD) clean
install:
	./scripts/install
