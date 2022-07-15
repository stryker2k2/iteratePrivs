/* Name: IteratePrivs.c
 * Description: Basic Template for Iterating Process Privileges
 * Author: @stryker2k2
 * Link: github.com/stryker2k2/iteratePrivs
 * Version: 1.0.1
 * Compile: gcc IteratePrivs.c -o IteratePrivs.exe
 * Execution: IteratePrivs.exe
 */

#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

HANDLE token;
TOKEN_PRIVILEGES tokenPrivs;
DWORD TokenPrivsLength;
LUID myLUID;
LPWSTR privName;
DWORD size = MAXDWORD32;

int main ()
{
  if(!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token)) {
    printf("[-] Failed to open current process\n");
    printf("[-] %lu\n", GetLastError());
  }

  if(!GetTokenInformation(token, TokenPrivileges, &tokenPrivs, 0, &TokenPrivsLength))
  {
    if(!GetTokenInformation(token, TokenPrivileges, &tokenPrivs, TokenPrivsLength, &TokenPrivsLength))
    {
      printf("[-] Failed to open current process token\n");
      printf("[-] Error Code: %ld\n", GetLastError());
      printf("[-] Token Info Size: %ld\n", TokenPrivsLength);
      CloseHandle(token);
    }
  }

  printf("[+] Privilege Count: %ld\n", tokenPrivs.PrivilegeCount);

  if (tokenPrivs.PrivilegeCount > 0)
  {
    int i;
    for (i = 0; i < (int)tokenPrivs.PrivilegeCount; i++)
    {
      myLUID = tokenPrivs.Privileges[i].Luid;

      //printf("[+] myLUID is: 0x%04X%04X\n", myLUID.HighPart, myLUID.LowPart);
      LookupPrivilegeNameW(NULL, &myLUID, privName, &size);
      printf("[+] Privilege Name: %ls (0x%04lX%04lX)\n", privName, myLUID.HighPart, myLUID.LowPart);
    }
  }
}
