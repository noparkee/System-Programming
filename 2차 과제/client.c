#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "pthread.h"
#include "sys/timeb.h"

#define BUF_LEN	500

int atsign_counting(const char * const buf, size_t len){
	int i;
	int n = 0;
	for (i=0; i<len; i++){
		if(buf[i] == '@')
			n++;	
	}		
	return n;
}

int main(int argc, char *argv[]){
	char buffer[BUF_LEN];
	struct sockaddr_in server_addr, client_addr;
	int server_fd, client_fd;
	int msg_size;
	int atsign_count = 0;
	struct tm* t;
	struct timeb timebuffer;
	int milisec;

	int port_num = 1111;
	
	FILE *fp;
	char fn[30];
	
	for (int i = 0; i<8; i++){
		if((client_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
			printf("Client: Can't open stream socket\n");
			exit(0);
		}

		memset(&server_addr, 0, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr("192.168.211.3");
		server_addr.sin_port = htons(port_num);	

		if(connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
			printf("Connection failed %d\n", port_num);	
		}
		else{
			printf("Connection %d\n", port_num);
			sprintf(fn, "%d-%d.txt", port_num, client_fd); 
			printf("%s\n", fn);
			fp = fopen(fn, "a");
			while( 0 < (msg_size = read(client_fd, buffer, BUF_LEN))){		
				atsign_count += atsign_counting(buffer, msg_size);
				if (atsign_count >= 5)
					break;
				if(fp != NULL){
					time_t tnow;
					time(&tnow);
					t = (struct tm*) localtime(&tnow);
					ftime(&timebuffer);
					milisec = timebuffer.millitm;
					fprintf(fp, "%02d:%02d:%02d.%03d|%d|%s\n", t->tm_hour, t->tm_min, t->tm_sec, milisec, msg_size, buffer); 			
				}
				memset(buffer, 0x00, sizeof(buffer));
			}
			fclose(fp);
			close(client_fd);
			atsign_count = 0;

		}
		
		port_num += 1111;
	}
	
	return 0;
}
