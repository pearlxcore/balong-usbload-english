// Loader usbloader.bin through the emergency port for modems on the Balong V7R2 platform.//
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef WIN32
//%%%%
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#else
//%%%%
#include <windows.h>
#include <setupapi.h>
#include "getopt.h"
#include "printf.h"
#endif

#include "parts.h"
#include "patcher.h"


#ifndef WIN32
int siofd;
struct termios sioparm;
#else
static HANDLE hSerial;
#endif
FILE* ldr;


//*************************************************
// * HEX-dump of the memory area *
//*************************************************

void dump(unsigned char buffer[],int len) {
int i,j;
unsigned char ch;

printf("\n");
for (i=0;i<len;i+=16) {
  printf("%04x: ",i);
  for (j=0;j<16;j++){
   if ((i+j) < len) printf("%02x ",buffer[i+j]&0xff);
   else printf("   ");}
  printf(" *");
  for (j=0;j<16;j++) {
   if ((i+j) < len) {
	   // byte conversion for character mapping    ch=buffer[i+j];
    if ((ch < 0x20)||((ch > 0x7e)&&(ch<0xc0))) putchar('.');
    else putchar(ch);
   } 
   // fill with spaces for incomplete lines   else printf(" ");
  }
  printf("*\n");
 }
}


//*************************************************
// * Calculate the checksum of the command packet
//*************************************************
void csum(unsigned char* buf, int len) {

unsigned  int i,c,csum=0;

unsigned int cconst[]={0,0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF};

for (i=0;i<(len-2);i++) {
  c=(buf[i]&0xff);
  csum=((csum<<4)&0xffff)^cconst[(c>>4)^(csum>>12)];
  csum=((csum<<4)&0xffff)^cconst[(c&0xf)^(csum>>12)];
}  
buf[len-2]=(csum>>8)&0xff;
buf[len-1]=csum&0xff;
  
}

//*************************************************
// * Sending a command packet to the modem
//*************************************************
int sendcmd(unsigned char* cmdbuf, int len) {

unsigned char replybuf[1024];
unsigned int replylen;

#ifndef WIN32
csum(cmdbuf,len);
write(siofd,cmdbuf,len);  // send command
tcdrain(siofd);
replylen=read(siofd,replybuf,1024);
#else
    DWORD bytes_written = 0;
    DWORD t;

    csum(cmdbuf, len);
    WriteFile(hSerial, cmdbuf, len, &bytes_written, NULL);
    FlushFileBuffers(hSerial);

    t = GetTickCount();
    do {
        ReadFile(hSerial, replybuf, 1024, (LPDWORD)&replylen, NULL);
    } while (replylen == 0 && GetTickCount() - t < 1000);
#endif
if (replylen == 0) return 0;    
if (replybuf[0] == 0xaa) return 1;
return 0;
}

//*************************************
// Open and configure the serial port
//*************************************

int open_port(char* devname) {

//============= Linux ========================  
#ifndef WIN32

int i,dflag=1;
char devstr[200]={0};

// Instead of the full name of the device, it is allowed to transmit only the ttyUSB port number

// Check the device name for non-digital characters
for(i=0;i<strlen(devname);i++) {
  if ((devname[i]<'0') || (devname[i]>'9')) dflag=0;
}
// If the line contains only numbers, add the prefix / dev / ttyUSB
if (dflag) strcpy(devstr,"/dev/ttyUSB");
// copy the device name
strcat(devstr,devname);

siofd = open(devstr, O_RDWR | O_NOCTTY |O_SYNC);
if (siofd == -1) return 0;

bzero(&sioparm, sizeof(sioparm)); // prepare termios attribute block
sioparm.c_cflag = B115200 | CS8 | CLOCAL | CREAD ;
sioparm.c_iflag = 0;  // INPCK;
sioparm.c_oflag = 0;
sioparm.c_lflag = 0;
sioparm.c_cc[VTIME]=30; // timeout  
sioparm.c_cc[VMIN]=0;  
tcsetattr(siofd, TCSANOW, &sioparm);
return 1;

//============= Win32 ========================  
#else
    char device[20] = "\\\\.\\COM";
    DCB dcbSerialParams = {0};
    COMMTIMEOUTS CommTimeouts;

    strcat(device, devname);
    
    hSerial = CreateFileA(device, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hSerial == INVALID_HANDLE_VALUE)
        return 0;

    ZeroMemory(&dcbSerialParams, sizeof(dcbSerialParams));
    dcbSerialParams.DCBlength=sizeof(dcbSerialParams);
    dcbSerialParams.BaudRate=CBR_115200;
    dcbSerialParams.ByteSize=8;
    dcbSerialParams.StopBits=ONESTOPBIT;
    dcbSerialParams.Parity=NOPARITY;
    dcbSerialParams.fBinary = TRUE;
    dcbSerialParams.fDtrControl = DTR_CONTROL_ENABLE;
    dcbSerialParams.fRtsControl = RTS_CONTROL_ENABLE;
    if(!SetCommState(hSerial, &dcbSerialParams))
    {
        CloseHandle(hSerial);
        return 0;
    }

    CommTimeouts.ReadIntervalTimeout = MAXDWORD;
    CommTimeouts.ReadTotalTimeoutConstant = 0;
    CommTimeouts.ReadTotalTimeoutMultiplier = 0;
    CommTimeouts.WriteTotalTimeoutConstant = 0;
    CommTimeouts.WriteTotalTimeoutMultiplier = 0;
    if (!SetCommTimeouts(hSerial, &CommTimeouts))
    {
        CloseHandle(hSerial);
        return 0;
    }

    return 1;
#endif
}

//*************************************
// * Search for linux kernel in partition image
//*************************************
int locate_kernel(char* pbuf, uint32_t size) {
  
int off;

for(off=(size-8);off>0;off--) {
  if (strncmp(pbuf+off,"ANDROID!",8) == 0) return off;
}
return 0;
}

#ifdef WIN32

DEFINE_GUID(GUID_DEVCLASS_PORTS, 0x4D36E978, 0xE325, 0x11CE, 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18);

static int find_port(int* port_no, char* port_name)
{
  HDEVINFO device_info_set;
  DWORD member_index = 0;
  SP_DEVINFO_DATA device_info_data;
  DWORD reg_data_type;
  char property_buffer[256];
  DWORD required_size;
  char* p;
  int result = 1;

  device_info_set = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTS, NULL, 0, DIGCF_PRESENT);

  if (device_info_set == INVALID_HANDLE_VALUE)
    return result;

  while (TRUE)
  {
    ZeroMemory(&device_info_data, sizeof(SP_DEVINFO_DATA));
    device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

    if (!SetupDiEnumDeviceInfo(device_info_set, member_index, &device_info_data))
      break;

    member_index++;

    if (!SetupDiGetDeviceRegistryPropertyA(device_info_set, &device_info_data, SPDRP_HARDWAREID,
             &reg_data_type, (PBYTE)property_buffer, sizeof(property_buffer), &required_size))
      continue;

    if (strstr(_strupr(property_buffer), "VID_12D1&PID_1443") != NULL)
    {
      if (SetupDiGetDeviceRegistryPropertyA(device_info_set, &device_info_data, SPDRP_FRIENDLYNAME,
              &reg_data_type, (PBYTE)property_buffer, sizeof(property_buffer), &required_size))
      {
        p = strstr(property_buffer, " (COM");
        if (p != NULL)
        {
          *port_no = atoi(p + 5);
          strcpy(port_name, property_buffer);
          result = 0;
        }
      }
      break;
    }
  }

  SetupDiDestroyDeviceInfoList(device_info_set);

  return result;
}

#endif

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

void main(int argc, char* argv[]) {

unsigned int i,res,opt,datasize,pktcount,adr;
int bl;    // current block
unsigned char c;
int fbflag=0, tflag=0, mflag=0, bflag=0, cflag=0;
int koff;  // offset to ANDROID header
char ptfile[100];

FILE* pt;
char ptbuf[2048];
uint32_t ptoff;

struct ptable_t* ptable;

unsigned char cmdhead[14]={0xfe,0, 0xff};
unsigned char cmddata[1040]={0xda,0,0};
unsigned char cmdeod[5]={0xed,0,0,0,0};

// list of sections that need to set the file flag
uint8_t fileflag[41];

struct {
	int lmode; // boot mode: 1 - direct start, 2 - through restarting A-core
	int size; // size of the component
	int adr; // address of the component load into memory
	int offset; // offset to the component from the beginning of the file
	char * pbuf; // buffer for loading the component image
} blk[10];


#ifndef WIN32
unsigned char devname[50]="/dev/ttyUSB0";
#else
char devname[50]="";
DWORD bytes_written, bytes_read;
int port_no;
char port_name[256];
#endif

#ifndef WIN32
bzero(fileflag,sizeof(fileflag));
#else
memset(fileflag, 0, sizeof(fileflag));
#endif

while ((opt = getopt(argc, argv, "hp:ft:ms:bc")) != -1) {
  switch (opt) {
   case 'h': 
	   
	   printf("\n\
Balong-chipset USB Downloader Utility V2.03, (c) forth32, 2015\n\
Port for Windows 32bit (c) rust3028, 2016\n\
English Version by Izat (pearlxcore), 2020\n");
	   printf("\n- The utility is designed for emergency USB-boot devices on the Balong V7 chipset\n\
- Usage : %s [keys] <filename to load>\n\
- The following keys are valid:\n\n"
#ifndef WIN32
"-p <tty>    - serial port for communication with the bootloader (default/dev/ttyUSB0)\n"
#else
"-p <tty>    - serial port to communicate with the bootloader\n"
#endif
"-f          - load usbloader only to fastboot (without running Linux)\n\
-b          - like -f, additionally disable the check for defective blocks when erasing\n\
-t <file>   - take the partition table from the specified file\n\
-m          - show boot loader partition table and exit\n\
-s n        - set the file flag for the n section (the key can be specified several times)\n\
-c          - do not automatically patch partitions\n\
", argv[0]);
    return;

   case 'p':
    strcpy(devname,optarg);
    break;

   case 'f':
     fbflag=1;
     break;

   case 'c':
     cflag=1;
     break;

   case 'b':
     fbflag=1;
     bflag=1;
     break;

   case 'm':
     mflag=1;
     break;

   case 't':
     tflag=1;
     strcpy(ptfile,optarg);
     break;

   case 's':
     i=atoi(optarg);
     if (i>41) {
		 printf("\n[*] Section #%i does not exist\n", i);
		 return;
     }
     fileflag[i]=1;
     break;
     
   case '?':
   case ':':  
     return;
    
  }
}  

printf("\n\
Balong-chipset USB Downloader Utility V2.03, (c) forth32, 2015\n\
Port for Windows 32bit (c) rust3028, 2016\n\
English Version (c) Izat (pearlxcore), 2020\n");


if (optind>=argc) {
	printf("\n[*] File name not specified for download\n");
	return;
}  

ldr=fopen(argv[optind],"rb");
if (ldr == 0) {
	printf("\n[*] Open error %s\n", argv[optind]);
	return;
}

// Check the usloader signature
fread(&i,1,4,ldr);
if (i != 0x20000) {
	printf("\n[*] File %s not a usbloader bootloader\n", argv[optind]);
	return;
}  

fseek(ldr,36,SEEK_SET); // start block descriptors to load

// parse the header

fread(&blk[0],1,16,ldr);  // raminit
fread(&blk[1],1,16,ldr);  // usbldr

//---------------------------------------------------------------------
// Read components into memory
for(bl=0;bl<2;bl++) {

	// allocate memory for the full image of the section
	blk[bl].pbuf=(char*)malloc(blk[bl].size);

	// read the partition image into memory
	fseek(ldr,blk[bl].offset,SEEK_SET);
  res=fread(blk[bl].pbuf,1,blk[bl].size,ldr);
  if (res != blk[bl].size) {
	  printf("\n[*] Unexpected end of file: read %i was expected %i\n", res, blk[bl].size);
	  return;
  }
  if (bl == 0) continue; // for raminit nothing more needs to be done

  //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
  // fastboot-патч
  if (fbflag) {
    koff=locate_kernel(blk[bl].pbuf,blk[bl].size);
    if (koff != 0) {
      blk[bl].pbuf[koff]=0x55; // patch signatures
      blk[bl].size=koff+8; // cut the partition to the beginning of the kernel
    }
    else {
		printf("\n[*] There is no ANDROID component in the loader - fastboot download is not possible\n");
		exit(0);
    }    
  }  

  //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
// Looking for partition table in the bootloader
  ptoff=find_ptable_ram(blk[bl].pbuf,blk[bl].size);
  
  //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
// patch partition table
  if (tflag) {
    pt=fopen(ptfile,"rb");
    if (pt == 0) { 
		printf("\n[*] File not found %s - cannot replace partition table\n", ptfile);
		return;
    }  
    fread(ptbuf,1,2048,pt);
    fclose(pt);
    if (memcmp(headmagic,ptbuf,sizeof(headmagic)) != 0) {
		printf("\n[*] File %s not a partition table\n", ptfile);
		return;
    }  
    if (ptoff == 0) {
		printf("\n[*] No partition table found in bootloader - cannot be replaced");
		return;
    }
    memcpy(blk[bl].pbuf+ptoff,ptbuf,2048);
  }
  ptable=(struct ptable_t*)(blk[bl].pbuf+ptoff);
  
  //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
// Patch file flags
  for(i=0;i<41;i++) {
    if (fileflag[i]) {
      ptable->part[i].nproperty |= 1;
    }  
  }  

  //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
// Display partition table
  if (mflag) {
    if (ptoff == 0) {
		printf("\n[*] No partition table found - no map output possible\n");
		return;
    }
    show_map(*ptable);
    return;
  }

  // Erase procedure patch to ignore the badblocks
  if (bflag) {
    res=perasebad(blk[bl].pbuf, blk[bl].size);
    if (res == 0) { 
		printf("\n[*] Isbad signature not found - cannot load\n");
		return;
    }  
  }
  // Delete the flash_eraseall procedure
  if (!cflag) {
    res=pv7r2(blk[bl].pbuf, blk[bl].size)+ pv7r11(blk[bl].pbuf, blk[bl].size) + pv7r1(blk[bl].pbuf, blk[bl].size) + pv7r22(blk[bl].pbuf, blk[bl].size) + pv7r22_2(blk[bl].pbuf, blk[bl].size);
	if (res != 0)  printf("\n[*] *Removed procedure flash_eraseal by offset %08x", res);
	else {
		printf("\n[*] The eraseall procedure was not found in the bootloader - use the –c key to download without a patch!\n");
		return;
   }    
  }   
     
  
}

//---------------------------------------------------------------------

#ifdef WIN32
if (*devname == '\0')
{
	printf("\n[*] Searching emergency boot port...\n");

  if (find_port(&port_no, port_name) == 0)
  {
    sprintf(devname, "%d", port_no);
	printf("[*] Port found : \"%s\"\n", port_name);
  }
  else
  {
	  printf("[*] Port not detected!\n");
	  return;
  }
}
#endif

if (!open_port(devname)) {
	printf("\n\n[*] Serial port does not open\n");
	return;
}  


// Check the boot port
c=0;
#ifndef WIN32
write(siofd,"A",1);
res=read(siofd,&c,1);
#else
    WriteFile(hSerial, "A", 1, &bytes_written, NULL);
    FlushFileBuffers(hSerial);
    Sleep(100);
    ReadFile(hSerial, &c, 1, &bytes_read, NULL);
#endif
if (c != 0x55) {
	printf("[*] Port is not in USB Boot mode\n");
	return;
}  

//----------------------------------
// main load loop - load all blocks found in the header
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    

printf("\nComponent    Address    Size   Process\n------------------------------------------\n");

for(bl=0;bl<2;bl++) {

  datasize=1024;
  pktcount=1;


  // form the block start packet
  *((unsigned int*)&cmdhead[4])=htonl(blk[bl].size);
  *((unsigned int*)&cmdhead[8])=htonl(blk[bl].adr);
  cmdhead[3]=blk[bl].lmode;
  
  // send the package start block
  res=sendcmd(cmdhead,14);
  if (!res) {
	  printf("\n[*] Modem rejected header packet\n");
	  return;
  }  

  
  // ---------- Block by block data download ---------------------
  for(adr=0;adr<blk[bl].size;adr+=1024) {

	  // form the size of the last loaded package
	  if ((adr+1024)>=blk[bl].size) datasize=blk[bl].size-adr;  

	  printf("\r %s    %08x %8i   %i%%", bl ? "usbboot" : "raminit", blk[bl].adr, blk[bl].size, (adr + datasize) * 100 / blk[bl].size);

	// prepare the data packet
	cmddata[1]=pktcount;
    cmddata[2]=(~pktcount)&0xff;
    memcpy(cmddata+3,blk[bl].pbuf+adr,datasize);
    
    pktcount++;
    if (!sendcmd(cmddata,datasize+5)) {
		printf("[*] Modem rejected data packet");
		return;
    }  
  }
  free(blk[bl].pbuf);

  // We form the end of data packet
  cmdeod[1]=pktcount;
  cmdeod[2]=(~pktcount)&0xff;

  if (!sendcmd(cmdeod,5)) {
	  printf("[*] Modem rejects data end packet");
  }
printf("\n");  
} 
printf("\n[*] Download complete\n");
}


