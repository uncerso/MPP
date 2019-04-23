#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <thread>
#include <chrono>

using namespace std;

int check(char c) {
	if (c == 'a') return 0;
	if (c == 'b') return 1;
	if (c == 'c') return 2;
	return -1;
}

void shift(char* msg, size_t len) {
	for(size_t i = 0; i < len; ++i)
		msg[i] = msg[i + 1];
}

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 2;
	constexpr int maxlen = 60;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;

	char msg[maxlen+1];
	memset(msg, 0, sizeof(msg));
	while(true) {
		this_thread::sleep_for(50ms);
		int err = recv(sock_id, msg, maxlen, 0);
		if (err != -1) {
			if (*msg == '!') {
				cout << msg+1 << endl;
				continue;
			}
			if (check(*msg) != -1) {
				char c = *msg;
				size_t len = strlen(msg);
				shift(msg, len);
				--len;
				msg[len] = c;
				if (len == maxlen) continue;
				++len;
				msg[len] = c;
				send(sock_id, msg, strlen(msg) + 1, 0);
			}
		}
	}
	return 0;
}