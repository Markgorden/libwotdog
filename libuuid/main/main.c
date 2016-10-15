#include <stdio.h>
#include <stdlib.h>
#include "../libc_uuid/get_uuid.h"

int main() 
{
  char str[37];
  get_uuid(str);
  printf("%s\n", str);
  printf("\n");
}


