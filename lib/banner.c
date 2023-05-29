#include <stdio.h>

int print_banner(void) {

  FILE *fp;
  char line[4];

  fp = fopen("lib/banner.txt", "r");

  if (fp == NULL) {
    printf("[-] Error when trying to read banner.txt file\n"); 
    return 1;
  }

  while (fgets(line, sizeof(line), fp)) {
    printf("%s", line);
  }

  fclose(fp);

  return 0;
}
