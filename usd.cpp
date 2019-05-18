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
#include <sys/wait.h>

using namespace std;

void sigChildHandler(int signo) {
	int status;
	while (1) {
		pid_t pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) break;
	}
}

struct msg_type {
	int code;
	int value;
};

void run_apps(const char * name) {
	switch (fork()) {
		case -1 :
			cerr << "Cannot fork\n";
			break;
		case 0:
			execlp(name, name+2, nullptr);
			cerr << "Cannot run " << name << "\n";
			break;
		default:
			break;
	}
}

int main(int argc, char *argv[]) {
	constexpr int socket_family = 41;
	constexpr int socket_type = 2;
	constexpr int socket_protocol = 0;
	constexpr int maxlen = 60;

	struct sigaction act;
	memset (&act, 0, sizeof(act));
	act.sa_handler = sigChildHandler;
 
	if (sigaction(SIGCHLD, &act, 0)) {
		cerr << "Sigaction error\n";
		return 1;
	}

	int sock_id = socket(socket_family, socket_type, socket_protocol);
	if (sock_id < 0) {
		cerr << "Cannot create socked, error: " << sock_id << '\n'; 
		return 0;
	}

	char msg[maxlen+1];
	memset(msg, 0, sizeof(msg));
	char app_name[7];
	memcpy(app_name, "./app_", 7);
	while (true) {
		int err = recv(sock_id, msg, maxlen, 0);
		if (err == 0) {
			auto p = reinterpret_cast<msg_type *>(msg);
			cout << "code: " <<p->code << " value: " << p->value << endl;
			if (p->code == 1) {
				app_name[5] = p->value + '0';
				run_apps(app_name);
			}
		}
	}
	return 0;
}