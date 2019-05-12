NAME = nc_kernel
OBJS = nc_kernel_module.o nc_queues.o
$(NAME)-objs += $(OBJS)
obj-m += $(NAME).o

.phony: all clean unload load build app1_ app2_ app3_ init_ usd_
all:
	make build
	make load
	make clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
unload:
	sudo rmmod $(NAME)
unloadFORCE:
	sudo rmmod --force $(NAME)
load:
	sudo insmod $(NAME).ko
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
usd_:
	g++ -Wall -O3 --std=c++17 usd.cpp -o usd

$(NAME).o : $(OBJS)
	ld -r -o $@ $^