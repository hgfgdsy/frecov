#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

char *buf;
int fildes[2];

int main(int argc, char *argv[]) {
  int fd = open("filesystem/fs.img",O_RDONLY);
  buf = (char *)mmap(NULL,1<<27,PROT_READ,MAP_SHARED,fd,0);
  short BPW = *(short *)&buf[0xb];
  char  WPC = buf[0xd];
  short reserved = *(short *)&buf[0xe];
  char nfat = buf[0x10];
  short pfat_s = -1;
  int pfat_l = -1;
  if(buf[0x16]!=0) pfat_s = *(short *)&buf[0x16];
  else pfat_l = *(int *)&buf[0x24];
  if(pfat_s == -1 && pfat_l == -1) {
	  printf("cao!!\n");
  }
  int pfat;
  if(pfat_s != -1) pfat = pfat_s;
  else pfat = pfat_l;
  int offset = BPW*(pfat*nfat+reserved);
  short size_s = -1;
  int size_l = -1;
  if(buf[0x13]!=0) size_s = *(short *)&buf[0x13];
  else size_l = *(int *)&buf[0x20];
  if(size_s == -1 && size_l == -1) {
	  printf("cao!!\n");
  }
  int size;
  if(size_s != -1) size = size_s;
  else size = size_l;
  printf("%x %x %x\n",size*BPW,WPC,offset);
  int my_total = (size-offset/BPW)/WPC;
  int pace = BPW*WPC;
  int my_pace = pace/32;
  char fname[400];
//  char shx[40];
  for(int i=0;i<my_total;i++){
	  for(int j=0;j<my_pace;j++){
		  int tof = offset + i*pace + 32*j;
		  if(buf[tof+8]=='B'&&buf[tof+9]=='M'&&buf[tof+10]=='P'){
			  short low,high;
			  low = *(short *)&buf[tof+0x1a];
			  high = *(short *)&buf[tof+0x14];
			  int ihigh = high;
			  int cof = (ihigh<<16) + low;
			  if(cof == 0) continue;
			  cof-=2;
			  int picture = offset + pace*cof;
			  printf("picture = %x %x %x\n",picture,cof,high);
			  if(buf[picture]!='B' || buf[picture+1]!='M')
				  continue;
			  int psize = *(int *)&buf[picture+2];
			  int fsize = *(int *)&buf[tof+0x1c];
			  if(psize!=fsize) continue;
//			  void *phead = (void *)buf[picture];
			  int tempj = j-1;
			  int ncnt = 0;
			  int label = 0;
			  char last;
			  while(tempj>=0){
				  int tempoff = tof-(j-tempj)*32;
				  for(int i=0;i<5;i++){
					  last = buf[tempoff + i*2 + 1];
					  if(buf[tempoff + i*2+1]!=0xff)
					          fname[ncnt++]=buf[tempoff + i*2+1];

				  }
				  for(int i=0xe;i<0x19;i+=2){
                                          last = buf[tempoff + i];
					  if(buf[tempoff + i]!=0xff)
						  fname[ncnt++]=buf[tempoff +i];
				  }
				  for(int i=0x1c;i<0x1f;i+=2){
					  last = buf[tempoff + i];
					  if(buf[tempoff + i]!=0xff)
						  fname[ncnt++]=buf[tempoff +i];
				  }
				  if(buf[tempoff]>>6&1) {
					  fname[ncnt] = '\0';
					  label=1;
					  break;
				  }
				  tempj--;
			  }
			  if(last == 0xff) continue;
			  if(label==0) continue;
			  printf("%s\n",fname);
		  }
		  else {
			  continue;
		  }
	  }
  }
  return 0;
}
