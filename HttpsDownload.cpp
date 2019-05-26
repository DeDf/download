
#include "download.h"

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

#ifdef _DEBUG
#pragma comment(linker, "\"/manifestdependency:type='Win32' name='Microsoft.VC80.CRT' version='8.0.50608.0' processorArchitecture='X86' publicKeyToken='1fc8b3b9a1e18e3b' language='*'\"")
#endif

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

// Simple structure to keep track of the handle,
//  and of what needs to be freed later.
typedef struct
{
    SOCKET socket;
    SSL *sslHandle;
    SSL_CTX *sslContext;
} connection;

// success : return 0
int ParseHttpsUrl(const char *url, OUT char *pchHost, OUT USHORT *port, OUT char **ppfile)
{
    if(!url || !pchHost || !ppfile || !port)
        return -1;

    pchHost[0] = 0;

    char *p = (char *)url;

    ULONG UrlLen = (ULONG)strlen(p);

    if(!strncmp(p, "https://", sizeof("https://")-1))
    {
        p      += sizeof("https://")-1;
        UrlLen -= sizeof("https://")-1;
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

// Establish a connection using an SSL layer
connection *sslConnect (const char *host, USHORT port)
{
    connection *c = (connection *)malloc(sizeof(connection));
    if (c)
    {
        c->sslHandle = NULL;
        c->sslContext = NULL;

        c->socket = ConnectTo(host, port);
        if (c->socket)
        {
            SSL_load_error_strings ();
            SSL_library_init ();
            OpenSSL_add_all_algorithms();

            // New context saying we are a client, and using SSL 2 or 3
            c->sslContext = SSL_CTX_new (SSLv23_client_method ());
            if (c->sslContext == NULL)
                ERR_print_errors_fp (stderr);

            // Create an SSL struct for the connection
            c->sslHandle = SSL_new (c->sslContext);
            if (c->sslHandle == NULL)
                ERR_print_errors_fp (stderr);

            // Connect the SSL struct to our connection
            if (!SSL_set_fd (c->sslHandle, (int)c->socket))
                ERR_print_errors_fp (stderr);

            SSL_set_tlsext_host_name(c->sslHandle, host);

            // Initiate SSL handshake
            if (SSL_connect (c->sslHandle) != 1)
                ERR_print_errors_fp (stderr);
        }
        else
        {
            free(c);
            c = NULL;
            printf("Connect failed!\n");
        }
    }

    return c;
}

// Disconnect & free connection struct
void sslDisconnect (connection *c)
{
    if (c->socket)
        closesocket (c->socket);

    if (c->sslHandle)
    {
        SSL_shutdown (c->sslHandle);
        SSL_free (c->sslHandle);
    }

    if (c->sslContext)
        SSL_CTX_free (c->sslContext);

    free (c);
}

void HttpsDownload(const char *pUrl, const char *pchDownload2Path)
{
    char host[BUFFER_SIZE];
    USHORT port = PORT_443;
    char *file;

    if (ParseHttpsUrl(pUrl, host, &port, &file))
    {
        printf("ParseUrl() failed!\n");
        return;
    }

    connection *c = sslConnect (host, port);
    if (c == NULL)
        return;

    char *buf = (char*)malloc(DL_BUF_SIZE);
    ULONG len = sprintf_s(buf, DL_BUF_SIZE, HTTP_GET, file, host, port);
    buf[len] = 0;
    printf("%s", buf);

    len = SSL_write (c->sslHandle, buf, len);
    ERR_print_errors_fp (stderr);

    BOOLEAN ResultParse = 0;
L_GetFileLen:
    len = SSL_read (c->sslHandle, buf, DL_BUF_SIZE);
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
        len = SSL_read(c->sslHandle, buf, DL_BUF_SIZE);
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
        int tmp = SSL_read(c->sslHandle, buf + len + HeadLen, DL_BUF_SIZE - len - HeadLen);
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
            tmp = SSL_read(c->sslHandle, buf + sublen, DL_BUF_SIZE - sublen);
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
    sslDisconnect(c);
    WSACleanup();
}