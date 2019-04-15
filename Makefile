name = nc_kernel_module
obj-m += nc_kernel_module.o
.phony: all clean unload load build app1
all:
#	if [[$(lsmod | grep nc_kernel_module)]] then
#	make unload
	make build
	make load
	make clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
unload:
	sudo rmmod $(name)
unloadFORCE:
	sudo rmmod --force $(name)
load:
	sudo insmod $(name).ko
build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

app1_:
	g++ -Wall -O3 --std=c++17 app1.cpp -o app1