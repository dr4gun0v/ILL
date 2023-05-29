#include <stdlib.h>

void cyan() {
  printf("\033[0;36m");
}

void green() {
  printf("\033[0;32m");
}

void red() {
  printf("\033[0;31m");
}

void yellow() {
  printf("\033[0;33m");
}

void reset() {
  printf("\033[0m");
}
