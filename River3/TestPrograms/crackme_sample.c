#include <stdio.h>
#include <stdint.h>

static uint8_t inputBuf[1 << 20];

int RIVERTestOneInput(const char* data, const int size)
{
  if (data[0] == 'x')
  {
     if (data[1] == 'y')
        return 2;
     else
    	return 1;
  }
  return 0;
}

int main(int ac, const char **av)
{
  return RIVERTestOneInput((char *)inputBuf, 5);
}

