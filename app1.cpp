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

void shift(char* msg)
{
	char first = msg[0];
	for(size_t i = 0; i < strlen(msg); i++)
		msg[i] = msg[i + 1];
	msg[strlen(msg) - 1] = first;
}

void show_result(char* msg)
{
	cout << msg << endl;
}

bool check_string(char* msg)
{
	if (msg[0] == 'a')
		return true;
	else
		return false;
}

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 2;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;

	while(true){
		char msg[512];
		memset(msg, 0, sizeof(msg));
		int err = recv(sock_id, msg, sizeof(msg), 0);
		if (err == -1) {
			this_thread::sleep_for(1ms);
		}
		else {
			if (check_string(msg)) {
				shift(msg);
				int err = send(sock_id, msg, strlen(msg) + 1, 0);
				if (err == -1) {
					cout << "sending failed\n";
					exit(0);
				}
			}
			else {
				show_result(msg);
			}
		}
	}

	return 0;
}