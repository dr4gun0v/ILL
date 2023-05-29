#include <stdio.h>
#include <sys/utsname.h>
#include <string.h>

#include "lib/banner.c"
#include "lib/color.c"


typedef struct {
  int kernel;
  int limit_kernel;
  char prefix[2];
  char distro[25];
  char desc[60];
  char url[50];
 
} Vulnerabilities;


Vulnerabilities vulnerability[] = {
  { 2429, 24929, "=", "Linux", "'uselib()' Local Privilege Escalation", "https://www.exploit-db.com/exploits/895"},
  { 2690, 2611, "<=", "Linux", "'SYS_EPoll_Wait' Local Integer Overflow", "https://www.exploit-db.com/exploits/1397"},
  { 2613, 2617, "<=", "Linux", "'logrotate prctl()' Local Privilege Escalation", "https://www.exploit-db.com/exploits/2031"},
  { 2636, 2636, "<=", "Linux", "'RDS Protocol' Local Privilege Escalation", "https://www.exploit-db.com/exploits/15285"},
  { 2636, 2627, "<=", "RedHat x86-64", "'compat' Local Privilege Escalation ", "https://www.exploit-db.com/exploits/15024"},
  { 3190, 3130, "<=", "Ubuntu", "'overlayfs' Local Privilege Escalation (1)", "https://www.exploit-db.com/exploits/37292"},
  { 3000, 4330, "<=", "Ubuntu", "'overlayfs' Local Privilege Escalation (1)", "https://www.exploit-db.com/exploits/39230"},
  { 2634, 2636, "<=", "Linux", "'caps_to_root' Local Privilege Escalation", "https://www.exploit-db.com/exploits/15916"},
  { 2622, 4830, "<=", "Linux", "DirtyCow (1)", "https://www.exploit-db.com/exploits/40611"},
  { 2622, 4830, "<=", "Linux", "DirtyCow (2)", "https://www.exploit-db.com/exploits/40839"},
  { 4150, 5117, "<=", "Linux", "'PTRACE_TRACEME' pkexec Local Privilege Escalation ", "https://www.exploit-db.com/exploits/47163"},
  { 5110, 5190, "<=", "Linux", "CVE-2023-0386 ", "https://github.com/chenaotian/CVE-2023-0386"},
};


int starts_with(const char *str, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    return strncmp(str, prefix, prefix_len) == 0;
}


char* remove_chars(char *str, const char *chars) {
    int len = strlen(str);
    int j = 0;
    char* result = malloc(len + 1);
    for (int i = 0; i < len; i++) {
        if (!strchr(chars, str[i])) {
            result[j++] = str[i];
        }
    }
    result[j] = '\0'; // We use \0 to indicate NULL
    return result;
}


void check_vulnerabilities(char* distro_name, char* kernel_version) {

  // Get the number of vulnerabilities from the struct
  int num_vulnerabilities = sizeof(vulnerability) / sizeof(Vulnerabilities);

  char* cleaned_kernel_version = remove_chars(kernel_version, ".-lts");
  
  // Extract the version number from the cleaned kernel version string
  int version;
  sscanf(cleaned_kernel_version, "%d", &version);
  free(cleaned_kernel_version);

  for(int i = 0; i < num_vulnerabilities; i++) {
    if(starts_with(vulnerability[i].prefix, "=") && vulnerability[i].kernel == version) {
      green();

      printf("\n\n* Distribution: %s\n"
        "* Description: %s\n"
        "* Exploit: %s", vulnerability[i].distro, vulnerability[i].desc, vulnerability[i].url);
    }

    if(starts_with(vulnerability[i].prefix, "<=") && version <= vulnerability[i].kernel || version <= vulnerability[i].limit_kernel) {
      green();

      printf("\n\n* Distribution: %s\n"
        "* Description: %s\n"
        "* Exploit: %s", vulnerability[i].distro, vulnerability[i].desc, vulnerability[i].url);
    }
  }

  yellow();
  printf("\n\n[!] Finished");

  reset();
}


void get_distro(char* kernel_version) {

  char buffer[30];
  char distro_name[30];

  // There is any better way than reading the os-release?
  FILE *fp = fopen("/etc/os-release", "r");

  if (fp == NULL) {
    red();
    printf("[-] Error when trying to read os-release file");
  }

  // I know fgets is insecure and this code is probably vulnerable to BoF but, who cares? ¯\_(ツ)_/¯
  while (fgets(buffer, 30, fp)) {
    if(strncmp(buffer, "NAME=", 5) == 0) {

      // We need to escape the "" to get the clean distro name
      sscanf(buffer + 5, "\"%[^\"]\"", distro_name);
      yellow();
      printf("\n[!] Linux distribution: %s", distro_name);

      reset();
      break;
    }
  }

  fclose(fp);

  check_vulnerabilities(distro_name, kernel_version);
}


int check_os(void) {

  struct utsname unameData;

  if(uname(&unameData) == -1) {
    perror("uname");
    return 1;
  }

  if(strcmp(unameData.sysname, "Linux") == 0) {
    green();
    printf("\n[+] Linux system detected, checking the version...\n");

    // I will move this to the check_vulnerabilities probably
    char kernel_version[30];
    strcpy(kernel_version, unameData.release);

    yellow();
    printf("[!] Kernel version: %s", kernel_version);
    reset();

    get_distro(kernel_version);
  } else {
    red();
    printf("\n[-] This script doesn't support this OS, please run only on Linux\n");

    reset();
    return 1;
  }

  return 0;

}


int main(void) {
  cyan();
  print_banner();
  reset();

  check_os();

  return 0;
}
