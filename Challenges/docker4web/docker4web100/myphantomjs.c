#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	char cmd[1024] = "xvfb-run phantomjs ";
	int cmdLength = 1024;
	int lenCmd = strlen(cmd);
	
	cmdLength -= lenCmd;
	
	char *p = cmd + lenCmd;

	int i;
	for(i = 1; i < argc; i++){
		strcpy(p, argv[i]);
		cmdLength -= strlen(argv[i]);
		if(cmdLength <= 1){
			printf("no room\n");
			break;
		}
		p += strlen(argv[i]);
		*p = ' ';
		cmdLength--;
		p++;
	}

	//printf("%s", cmd);
	system(cmd);

	return 0;
}
