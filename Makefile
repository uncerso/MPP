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
app2_:
	g++ -Wall -O3 --std=c++17 app2.cpp -o app2
app3_:
	g++ -Wall -O3 --std=c++17 app3.cpp -o app3
init_:
	g++ -Wall -O3 --std=c++17 init.cpp -o init