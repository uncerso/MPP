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

void shift(char* msg) {
	size_t const size = strlen(msg);
	for(size_t i = 0; i < size; ++i)
		msg[i] = msg[i + 1];
}

void show_result(char* msg) {
	cout << '\t' << msg << endl;
}

bool check_string(char* msg) {
	size_t const size = strlen(msg);
	if (size == 0) {
		return false;
	}
	if (msg[0] == 'e' && size == 9) {
		shift(msg);
		return true;
	}
	if (msg[0] == 'a' && size == 6) {
		shift(msg);
		return true;
	}
	if (msg[0] == 'w' && size == 3) {
		shift(msg);
		return true;
	}
	return false;
}

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 2;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;

	char msg[50];
	memset(msg, 0, sizeof(msg));
	while(true) {
		this_thread::sleep_for(1ms);
		int err = recv(sock_id, msg, sizeof(msg), 0);
		if (err != -1) {
			cout << "Received msg\n";
			cout << "\tcontent: " << msg << endl;
			if (check_string(msg)) {
				cout << "\tfirst symbol is correct"<< endl;
				shift(msg);
				cout << "\tright shift: " << msg << endl;
				cout << "\t\tsending msg\n";
				int err = send(sock_id, msg, strlen(msg) + 1, 0);
				if (err == -1) {
					cout << "\t\tsending failed"<< endl;
					exit(0);
				}
				cout << "\t\tSuccessfully sended"<< endl;
			}
			else {
				cout << "\tthe first symbol is incorrect"<< endl;
				cout << "\tstopped at: "<< endl;
				show_result(msg);
			}
		}
	}

	return 0;
}