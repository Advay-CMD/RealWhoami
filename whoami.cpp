#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <iostream>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

void PrintSID() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::cerr << "Failed to open process token.\n";
        return;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    PTOKEN_USER user = (PTOKEN_USER)malloc(size);

    if (GetTokenInformation(token, TokenUser, user, size, &size)) {
        LPSTR sidStr = nullptr;
        if (ConvertSidToStringSidA(user->User.Sid, &sidStr)) {
            std::cout << "SID number     " << sidStr << "\n";
            LocalFree(sidStr);
        }
    }

    free(user);
    CloseHandle(token);
}

void PrintUsername() {
    char username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetUserNameA(username, &size)) {
        std::cout << "User           " << username << "\n";
    }
    else {
        std::cerr << "Failed to get username.\n";
    }
}

void PrintGroup() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::cerr << "Failed to open process token for groups.\n";
        return;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    PTOKEN_GROUPS groups = (PTOKEN_GROUPS)malloc(size);

    if (GetTokenInformation(token, TokenGroups, groups, size, &size)) {
        for (DWORD i = 0; i < groups->GroupCount; ++i) {
            SID_NAME_USE sidType;
            char name[256], domain[256];
            DWORD nameLen = sizeof(name), domainLen = sizeof(domain);

            if (LookupAccountSidA(nullptr, groups->Groups[i].Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                // Skip special or hidden groups if needed, or pick the first valid one
                std::cout << "Group          " << name << "\n";
                break;  // Show only one group
            }
        }
    }

    free(groups);
    CloseHandle(token);
}

int main() {
    std::cout << "Copyright Advay Shrivastava 2025\n" << std::endl;

    PrintUsername();
    PrintSID();
    PrintGroup();

    std::cout << "\nOK.\n";
    return 0;
}
