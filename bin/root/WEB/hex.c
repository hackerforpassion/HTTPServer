#include <stdio.h>

int main(void) {
  char *myString="FF";
  int myVal;
  sscanf(myString, "%x", &myVal);
  printf("The value was read in: it is %0x in hex, or %d in decimal\n", myVal, myVal);
}
