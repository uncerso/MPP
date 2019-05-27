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
	constexpr int socket_protocol = 3;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;
	char msg[maxlen+1];
	memset(msg, 0, sizeof(msg));
	while(true) {
		int err = recv(sock_id, msg, maxlen, 0);
		if (err)
			return 0;

		// cout << '!' << endl;
		++*msg;
		char c = *msg;
		if (!('a' <= c && c <= 'z'))
			*msg = 'a';
		send(sock_id, msg, maxlen+1, 0);
	}
	return 0;
}