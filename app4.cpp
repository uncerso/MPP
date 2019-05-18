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

#include "msg_size.h"

using namespace std;

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 4;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;

	int tt = 5;
	// int tt = 1000;
	char msg[maxlen+1];
	memset(msg, 0, sizeof(msg));
	for (int i = 0; i < amount_of_iterations; ++i) {
		int t = 0;
		while (recv(sock_id, msg, maxlen, 0) == -1);
		// cout << msg << endl;

		auto start = chrono::high_resolution_clock::now();
		send(sock_id, msg, maxlen+1, 0);
		while(t < tt) {
			int err = recv(sock_id, msg, maxlen, 0);
			if (err != -1) {
				// cout << msg << endl;
				++*msg;
				char c = *msg;
				if (!('a' <= c && c <= 'z'))
					*msg = 'a';
				++t;
				if (t < tt)
					send(sock_id, msg, maxlen+1, 0);
			}
		}

		auto finish = chrono::high_resolution_clock::now();
		cout << i <<' ' << chrono::duration_cast<chrono::nanoseconds>(finish-start).count() / 1e9 << endl;
	}
	return 0;
}