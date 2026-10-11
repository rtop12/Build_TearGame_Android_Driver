obj-m := uid_priv.o

all:
	$(MAKE) -C $(KERNEL_DIR) O=$(KERNEL_OUT) ARCH=$(KERNEL_ARCH) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) O=$(KERNEL_OUT) ARCH=$(KERNEL_ARCH) M=$(CURDIR) clean
