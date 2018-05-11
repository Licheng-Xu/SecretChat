#define SERVERPORT 2333
#define BUFFERSIZE 128
#define KEY "12345678"

#include <iostream>
#include <cstdlib>
#include <thread>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include "CDesOperate.h"

using namespace std;

char strStdinBuffer[BUFFERSIZE];
char strSocketBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];

//多次recv()确保整个数据块被顺利接收
ssize_t TotalRecv(int s, void *buf, size_t len, int flags)
{
    size_t nCurSize = 0;
    while (nCurSize < len)
    {
        ssize_t nRes = recv(s, (char *)buf + nCurSize, len - nCurSize, flags);
        if (nRes < 0 || nRes + nCurSize > len)
        {
            return -1;
        }
        nCurSize += nRes;
    }
    return nCurSize;
}
//一个线程负责接收密文消息，解密并输出到屏幕
void RecvPrint(int nSock, char *pRemoteName, char *pKey, CDesOperate &cDes)
{
    while (1)
    {
        bzero(&strSocketBuffer, BUFFERSIZE);
        int nLength = 0;
        nLength = TotalRecv(nSock, strSocketBuffer, BUFFERSIZE, 0);
        if (nLength != BUFFERSIZE)
        {
            break;
        }

        int nLen = BUFFERSIZE;
        cDes.Decry(strSocketBuffer, BUFFERSIZE, strDecryBuffer, nLen, pKey, 8);
        strDecryBuffer[BUFFERSIZE - 1] = 0;
        if (strDecryBuffer[0] != 0 && strDecryBuffer[0] != '\n')
        {
            printf("Receive message form <%s>: %s", pRemoteName, strDecryBuffer);
            if (0 == memcmp("quit", strDecryBuffer, 4))
            {
                printf("Quit!\n");
                close(nSock);
                exit(0);
            }
        }
    }
}

//另一个线程负责从标准输入读取消息，加密并发送到指定套接字
void ReadSend(int nSock, char *pRemoteName, char *pKey, CDesOperate &cDes)
{
    while (1)
    {
        bzero(&strStdinBuffer, BUFFERSIZE);
        while (strStdinBuffer[0] == 0)
        {
            if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL) //读取一行
            {
                continue;
            }
        }
        int nLen = BUFFERSIZE;
        cDes.Encry(strStdinBuffer, BUFFERSIZE, strEncryBuffer, nLen, pKey, 8);
        if (send(nSock, strEncryBuffer, BUFFERSIZE, 0) != BUFFERSIZE)
        {
            perror("send");
        }
        else
        {
            if (0 == memcmp("quit", strStdinBuffer, 4))
            {
                printf("Quit!\n");
                close(nSock);
                exit(0);
            }
        }
    }
}

void SecretChat(int nSock, char *pRemoteName, char *pKey)
{
    CDesOperate cDes;
    if (strlen(pKey) != 8)
    {
        printf("Key length error");
        return;
    }

    thread t1(ReadSend, nSock, pRemoteName, pKey, ref(cDes));
    thread t2(RecvPrint, nSock, pRemoteName, pKey, ref(cDes));

    t1.join();
    t2.join();
}

int main(int argc, char *args[])
{
    printf("Client or Server?\r\n");
    cin >> strStdinBuffer;
    if (strStdinBuffer[0] == 'c' || strStdinBuffer[0] == 'C')
    {
        //客户端
        char strIpAddr[16];
        printf("Please input the server address:\r\n");
        cin >> strIpAddr;
        int nConnectSocket;
        struct sockaddr_in sDestAddr;
        if ((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Socket");
            exit(errno);
        }
        bzero(&sDestAddr, sizeof(sDestAddr));
        sDestAddr.sin_family = AF_INET;
        sDestAddr.sin_port = htons(SERVERPORT);
        sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr);
        //连接服务器
        if (connect(nConnectSocket, (struct sockaddr *)&sDestAddr, sizeof(sDestAddr)) != 0)
        {
            perror("Connect ");
            exit(errno);
        }
        else
        {
            printf("Connect Success!  \nBegin to chat...\n");
            SecretChat(nConnectSocket, strIpAddr, const_cast<char *>(KEY));
        }
        close(nConnectSocket);
    }
    else
    {
        //服务器端
        int nListenSocket, nAcceptSocket;
        socklen_t nLength = 0;
        struct sockaddr_in sLocalAddr, sRemoteAddr;
        if ((nListenSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("socket");
            exit(1);
        }

        bzero(&sLocalAddr, sizeof(sLocalAddr));
        sLocalAddr.sin_family = PF_INET;
        sLocalAddr.sin_port = htons(SERVERPORT);
        sLocalAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(nListenSocket, (struct sockaddr *)&sLocalAddr, sizeof(struct sockaddr)) == -1)
        {
            perror("bind");
            exit(1);
        }
        if (listen(nListenSocket, 5) == -1)
        {
            perror("listen");
            exit(1);
        }
        printf("Listening...\n");
        nLength = sizeof(struct sockaddr);
        if ((nAcceptSocket = accept(nListenSocket, (struct sockaddr *)&sRemoteAddr, &nLength)) == -1)
        {
            perror("accept");
            exit(errno);
        }
        else
        {
            close(nListenSocket);
            printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(sRemoteAddr.sin_addr),
                   ntohs(sRemoteAddr.sin_port), nAcceptSocket);
            SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), const_cast<char *>(KEY));
            close(nAcceptSocket);
        }
    }
    return 0;
}