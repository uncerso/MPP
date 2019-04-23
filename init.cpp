#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 2;

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) return 0;

	string s;
	cout << ">> ";
	cin >> s;
	int err = send(sock_id, s.data(), s.size() + 1, 0);
	if (err == -1)
	{
		cout << "Failed\n";
		return 0;
	}
	cout << "Sended\n";

	return 0;
}