
#include "download.h"

// success : return 0
int ParseUrl(const char *url, OUT char *pchHost, OUT USHORT *port, OUT char **ppfile)
{
    if(!url || !pchHost || !ppfile || !port)
        return -1;

    pchHost[0] = 0;

    char *p = (char *)url;

    ULONG UrlLen = (ULONG)strlen(p);

    if(!strncmp(p, "http://", sizeof("http://")-1))
    {
        p      += sizeof("http://")-1;
        UrlLen -= sizeof("http://")-1;
    }
    else
    {
        return -1;
    }

    *ppfile = strchr(p, '/');
    if (*ppfile)
    {
        ULONG len = UrlLen - (ULONG)strlen(*ppfile);
        if (len < BUFFER_SIZE)
        {
            memcpy(pchHost, p, len);
            pchHost[len] = '\0';
        }
    }
    else
    {
        memcpy(pchHost, p, UrlLen);
        pchHost[UrlLen] = '\0';
    }

    // get port
    p = strchr(pchHost,':');
    if(p)
    {
        *port = atoi(p+1);
    }

    return 0;
}

BOOLEAN http_parse_result(const char *buf)
{
    char *p = (char*)strstr(buf, "HTTP/1.1");
    if (!p)
    {
        printf("http/1.1 not find!\n");
        return FALSE;
    }

    if(atoi(p + 9) != 200)
    {
        printf("result:\n%s\n", buf);
        return FALSE;
    }

    return TRUE;
}

ULONG GetFileLength(char *buf)
{
    char *p = strstr(buf, "Content-Length:");
    if (p)
    {
        p += sizeof("Content-Length:");
        return atoi(p);
    }

    return 0;
}

SOCKET ConnectTo(const char *host, USHORT port)  // done!
{
    WSADATA wsaData;
    if (!WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (s != -1)
        {
            struct hostent *he = gethostbyname(host);
            if (he)
            {
                struct sockaddr_in server_addr;
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(port);
                server_addr.sin_addr = *((struct in_addr *)he->h_addr);

                if (!connect(s, (struct sockaddr *)&server_addr, sizeof(server_addr)))
                    return s;
            }

            closesocket(s);
        }

        WSACleanup();
    }

    return NULL;
}

// void http_post(const char *url, const char *post_str)
// {
//     if (url && post_str)
//     {
//         char host[BUFFER_SIZE];
//         USHORT port = DEFAULT_PORT;
//         char *file;
// 
//         if (!ParseUrl(url, host, &port, &file))
//         {
//             SOCKET s = ConnectTo(host, port);
//             if (s)
//             {
//                 char lpbuf[BUFFER_SIZE*4];
//                 sprintf_s(lpbuf,sizeof(lpbuf),HTTP_POST,file,host,port,strlen(post_str),post_str);
// 
//                 send(s, lpbuf, (ULONG)strlen(lpbuf), 0);
//                 recv(s, lpbuf, sizeof(lpbuf), 0);
// 
//                 closesocket(s);
//                 WSACleanup();
//             }
//         }
//     }
// }

HANDLE CreateFileByUrlA(const char *pUrl, const char *pchDownload2Path)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char chFilePathName[MAX_PATH];

    if (pUrl)
    {
        char *pchFileName = strrchr((char *)pUrl, '/') + 1;
        sprintf_s(chFilePathName, sizeof(chFilePathName), "%s\\%s", pchDownload2Path, pchFileName);

        char *pT = strchr((char *)chFilePathName, '?');
        if (pT)
            *pT = 0;

        hFile = CreateFileA(chFilePathName, // FileName
            GENERIC_WRITE,
            FILE_SHARE_READ,          // share to read
            NULL,                     // no security
            CREATE_NEW,
            0,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("file %s have exist!\n", chFilePathName);
        }
        else
        {
            printf("%s :", chFilePathName);
        }
    }

    return hFile;
}

void Download(const char *pUrl, const char *pchDownload2Path)
{
    char host[BUFFER_SIZE];
    USHORT port = PORT_80;
    char *file;

    if (ParseUrl(pUrl, host, &port, &file))
    {
        return HttpsDownload(pUrl, pchDownload2Path);
    }

    SOCKET s = ConnectTo(host, port);
    if (s == NULL)
        return;

    char *buf = (char*)malloc(DL_BUF_SIZE);
    int len = sprintf_s(buf, DL_BUF_SIZE, HTTP_GET, file, host, port);
    if (len < 0)
        return;
    buf[len] = 0;
    printf("%s", buf);

    send(s, buf, len, 0);

    BOOLEAN ResultParse = 0;
L_GetFileLen:
    len = recv(s, buf, DL_BUF_SIZE, 0);
    if (len <= 0)
        return;

    if (!ResultParse)
    {
        if (!http_parse_result(buf))
            return;
        ResultParse = 1;
    }

    ULONG FileSize = GetFileLength(buf);
    if (!FileSize)
        goto L_GetFileLen;

    HANDLE hFile = CreateFileByUrlA(pUrl, pchDownload2Path);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    printf(" %d bytes\n\n", FileSize);

    char *p = strstr(buf, "\r\n\r\n");
    while (!p)
    {
        len = recv(s, buf, DL_BUF_SIZE, 0);
        if (len <= 0)
        {
            printf("\ndownload fail!\n");
            return;
        }
    }

    ULONG HeadLen = p + 4 - buf;
    len -= HeadLen;
    if (len)
        printf("Download : %dKB\n", len / 1024);

    while (FileSize > (ULONG)len &&
           DL_BUF_SIZE - (ULONG)len - HeadLen > 1024 )
    {
        int tmp = recv(s, buf + len + HeadLen, DL_BUF_SIZE - len - HeadLen, 0);
        if (tmp <= 0)
        {
            printf("\ndownload fail!\n");
            return;
        }
        else
        {
            len += tmp;
            printf("Download : %dKB\n", len / 1024);
        }
    }

    ULONG WriteCnt = 0;
    ULONG writen = 0;
    ULONG BytesWritten;
    WriteFile(hFile, buf + HeadLen, len, &BytesWritten, NULL);
    writen += BytesWritten;
    printf("WriteFile(%d)\n", ++WriteCnt);

    while (writen < FileSize)
    {
        ULONG sublen = 0;
        int tmp = 0;

        while (FileSize > (ULONG)len &&
            DL_BUF_SIZE - (ULONG)sublen > 1024 )
        {
            tmp = recv(s, buf + sublen, DL_BUF_SIZE - sublen, 0);
            if (tmp <= 0)
            {
                printf("\ndownload fail!\n");
                return;
            }
            else
            {
                sublen += tmp;
                len += tmp;
                printf("Download : %dKB\n", len / 1024);
            }
        }

        WriteFile(hFile, buf, sublen, &BytesWritten, NULL);
        writen += BytesWritten;
        printf("WriteFile(%d)\n", ++WriteCnt);
    }
    
    if (writen == FileSize)
    {
        printf("\ndownload complete~\n");
    }
    else
    {
        printf("\ndownload fail!\n");
    }

    CloseHandle(hFile);
    free(buf);
    closesocket(s);
    WSACleanup();
}

int main(int argc, char *argv[])
{
    if (argc == 2)
        Download(argv[1], "s:");
    else
        printf("usage : dl \"url\"\n"
               "    url include http/https.\n"
               "    sometime, \"\" is important!\n");

    getchar();
    return 0;
}