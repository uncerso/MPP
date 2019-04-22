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

	cout << "Socket creating..." << endl;
	int sock_id = socket(socket_family, socket_type, socket_protocol);
	cout << "\treturn id is " << sock_id << endl;
	if (sock_id < 0) return 0;

	string s;
	cout << ">> ";
	cin >> s;
	cout << "Sending message..." << endl;
	int err = send(sock_id, s.data(), s.size() + 1, 0);
	//cout << "\treturn value is " << err << endl;
	if (err == -1)
	{
		cout << "failed\n";
		return 0;
	}
	cout << "successfully";

	switch (errno) {
		case EINVAL:
			printf("EINVAL\n");
			break;
		case EBADF:
			printf("EBADF\n");
			break;
		case ENOTSOCK:
			printf("ENOTSOCK\n");
			break;
		case EFAULT:
			printf("EFAULT\n");
			break;
		case EMSGSIZE:
			printf("EMSGSIZE\n");
			break;
		case EAGAIN:
			printf("EAGAIN\n");
			break;
		case ENOBUFS:
			printf("ENOBUFS\n");
			break;
		case EINTR:
			printf("EINTR\n");
			break;
		case ENOMEM:
			printf("ENOMEM\n");
			break;
		case EPIPE:
			printf("EPIPE\n");
			break;
	
		default:
			cout << "Success!\n";
			break;
	}

	return 0;
}