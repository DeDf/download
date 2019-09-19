
#pragma once

#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")

#define BUFFER_SIZE 1024
#define DL_BUF_SIZE 2*1024*1024
#define HTTP_POST "POST %s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\nContent-Type:application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"
#define HTTP_GET   "GET %s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n\r\n"

#define PORT_80      80
#define PORT_443    443

SOCKET ConnectTo(const char *host, USHORT port);
BOOLEAN http_parse_result(const char *buf);
ULONG GetFileLength(char *buf);

int HttpsDownload(const char *pUrl, const char *pchDownload2Path);
HANDLE CreateFileByUrlA(const char *pUrl, const char *pchDownload2Path);
