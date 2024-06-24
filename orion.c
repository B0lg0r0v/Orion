#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <winhttp.h>
#include <stdbool.h>
#include <ws2tcpip.h>
#include <signal.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")


#define API_KEY "<YOUR API KEY>"

void printProcessNames(DWORD processID) {

    // Get a handle to the process.
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processID
    );

    // Get the process name.s
    if (NULL != hProcess) {

        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {

            TCHAR szProcessName[MAX_PATH];

            if (GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR))) {

                _tprintf(TEXT("\nPROCESS NAME: %s  (PID: %u)\n"), szProcessName, processID);

            }


        }
        else {
            printf("Error getting process name\n");
        }

    }

    // Release the handle to the process.
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }

}

// function to do a lookup of the IP address on VirusTotal with the API key to check if it is malicious
bool checkIP(const char* ipAddr) {

    struct in_addr IpAddr;
    int result = inet_pton(AF_INET, ipAddr, &IpAddr);
    if (result != 1) {
        printf("Invalid IP address format.\n");
        return false;
    }
    const char *ip = inet_ntoa(IpAddr);

    //printf("\DEBUG IP: %s\n", ip);

    // Initialize the WinHTTP session.
    HINTERNET hSession = WinHttpOpen(L"Orion Lookup/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {

        HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com",
            INTERNET_DEFAULT_HTTPS_PORT, 0);

        if (hConnect) {

            wchar_t path[256];
            wsprintfW(path, L"/api/v3/ip_addresses/%S", ip);
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);

            if (hRequest) {

                wchar_t headers[256];
                wsprintfW(headers, L"x-apikey: %S", API_KEY);
                WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
                if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {

                    if (WinHttpReceiveResponse(hRequest, NULL)) {


                        DWORD dwSize = 0;
                        DWORD dwDownloaded = 0;
                        LPSTR pszOutBuffer = NULL;
                        //LPSTR pszTotalBuffer = NULL;
                        DWORD totalSize = 0;

                        do {

                            // Check for available data.
                            dwSize = 0;

                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                                break;
                            }

                            // Allocate space for the buffer.
                            LPSTR tempBuffer = (LPSTR) realloc(pszOutBuffer, totalSize + dwSize + 1);

                            if (!tempBuffer) {

                                printf("Out of memory\n");
                                free(pszOutBuffer);
                                dwSize = 0;
                                break;
                            
                            } else {

                                pszOutBuffer = tempBuffer;
                            }


                            // Read the data.
                            if (!WinHttpReadData(hRequest, (LPVOID)(pszOutBuffer + totalSize),

                                dwSize, &dwDownloaded)) {
                                printf("Error %u in WinHttpReadData.\n", GetLastError());
                                free(pszOutBuffer);
                                break;
                            }

                            totalSize += dwDownloaded;
                            //printf("Total size: %d\n", totalSize);

                        } while (dwSize > 0);

                        if (pszOutBuffer) {

                            // parse the JSON response to check if the IP is malicious. Check for the string "last_analysis_stats".
                            const char* malicious = "\"last_analysis_stats\":";
                            char* pMalicious = strstr(pszOutBuffer, malicious);
                            if (pMalicious) {

                                // get the value of the malicious key
                                const char* pMaliciouskey = "\"malicious\":";
                                char* pMaliciousValue = strstr(pMalicious, pMaliciouskey);

                                if (pMaliciousValue) {

                                    pMaliciousValue += strlen(pMaliciouskey);
                                    int k = atoi(pMaliciousValue);

                                    if (k > 1) {

                                        //printf("\t(malicious) [%d]\n", k);
                                        return true;

                                    }
                                    else {

                                        //printf("\t(safe) [%d]\n", k);
                                        return false;
                                    }


                                }

                                free(pszOutBuffer);
                                pszOutBuffer = NULL; // Set PSZOutBuffer to NULL after freeing it
                            }

                        
                        }

                    //pszOutBuffer = NULL; // Set PSZOutBuffer to NULL after freeing it
                    }

                    WinHttpCloseHandle(hRequest);

                }

                WinHttpCloseHandle(hConnect);

            }

            WinHttpCloseHandle(hSession);

        }


    }

    return false;
}


int TCPOutboundConnections() {

    // PMIB_TCPTABLE2 Pointer to a MIB_TCPTABLE2 structure that contains a table of TCP connections.
    PMIB_TCPTABLE2 pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    char szLocalAddr[128] = { 0 };
    char szRemoteAddr[128] = { 0 };

    struct in_addr IpAddr;

    int i;

    ULONG ulSize = 0;

    // Allocate memory for the MIB_TCPTABLE structure.
    pTcpTable = (MIB_TCPTABLE2*)malloc(sizeof(MIB_TCPTABLE2));

    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        return -1;
    }

    ulSize = sizeof(MIB_TCPTABLE);

    if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
        ERROR_INSUFFICIENT_BUFFER) {
        free(pTcpTable);
        pTcpTable = (MIB_TCPTABLE2*)malloc(ulSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return -1;
        }
    }

    if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {

        for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {

            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
            
            if (inet_ntop(AF_INET, &IpAddr, szLocalAddr, sizeof(szLocalAddr)) == NULL) {
                perror("Local Address conversion error");
                continue; // Skip this entry on error
            }
            
            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
            
            if (inet_ntop(AF_INET, &IpAddr, szRemoteAddr, sizeof(szRemoteAddr)) == NULL) {
                perror("Remote Address conversion error");
                continue; // Skip this entry on error
            }


            if (strcmp(szLocalAddr, "127.0.0.1") == 0 || strcmp(szRemoteAddr, "127.0.0.1") == 0 ||
                strcmp(szLocalAddr, "0.0.0.0") == 0 || strcmp(szRemoteAddr, "0.0.0.0") == 0) {
                continue;
            }

            // check if the IP address is malicious with the checkIP function
            u_short localport = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            u_short remoteport = ntohs((u_short)pTcpTable->table[i].dwRemotePort);


            printf("\tLocal Port: %d\n", localport);
            //printf("DEBUG: %s\n", szRemoteAddr);
            printf("\tRemote Addr: %s:%d --> [%s]\n", szRemoteAddr, remoteport, checkIP(szRemoteAddr) ? "NALICIOUS" : "SAFE");
            printProcessNames(pTcpTable->table[i].dwOwningPid);
            //checkIP(szRemoteAddr);

        }

    }
    else {

        printf("\tGetTcpTable2 failed with %d\n", dwRetVal);
        free(pTcpTable);
        return -1;
    }

    if (pTcpTable != NULL) {
        free(pTcpTable);
        pTcpTable = NULL;
    }

    return 0;

}

void signalHandler(int signalNumber) {
    if (signalNumber == SIGINT) {
        printf("\nYou pressed Ctrl+C. Exiting...\n");
        exit(0); 
    }
}

int main() {

    signal(SIGINT, signalHandler);
    
    printf("\nORION v0.1\n");
    printf("Author: B0lg0r0v\n");
    printf("https://arthurminasyan.com/\n\n");
    Sleep(2000);  

    TCPOutboundConnections();
    
    return 0;

}