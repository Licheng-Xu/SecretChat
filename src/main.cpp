#define SERVERPORT 6666
#define BUFFERSIZE 128
#define DESKEYLENGTH 8

#include <iostream>
#include <cstdlib>
#include <thread>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "CDesOperate.h"
#include "CRSASection.h"

using namespace std;

char strStdinBuffer[BUFFERSIZE];
char strSocketBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];

char strDesKey[DESKEYLENGTH];
PublicKey cRsaPublicKey;

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

//生成随机的DES密钥
void GerenateDesKey(char *strDesKey)
{
    for (int i = 0; i < sizeof(strDesKey); i++)
        strDesKey[i] = rand() % 256;
}

void SecretChat(int nSock, char *pRemoteName, char *pKey)
{
    CDesOperate cDes;
    if (strlen(pKey) != DESKEYLENGTH)
    {
        printf("Key length error");
        return;
    }
    fd_set cHandleSet;
    timeval tv;
    int nRet;
    while (1)
    {
        //初始化相关变量
        FD_ZERO(&cHandleSet);
        FD_SET(nSock, &cHandleSet);
        FD_SET(0, &cHandleSet);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        nRet = select(nSock > 0 ? nSock + 1 : 1, &cHandleSet, NULL, NULL, &tv);
        if (nRet < 0)
        {
            printf("Select ERROR!\n");
            break;
        }
        if (0 == nRet)
        {
            continue;
        }
        //判断套接字是否有io操作
        if (FD_ISSET(nSock, &cHandleSet))
        {
            bzero(&strSocketBuffer, BUFFERSIZE);
            int nLength = 0;
            nLength = TotalRecv(nSock, strSocketBuffer, BUFFERSIZE, 0);
            if (nLength != BUFFERSIZE)
            {
                break;
            }
            else
            {
                int nLen = BUFFERSIZE;
                //解密并显示到屏幕上
                cDes.Decry(strSocketBuffer, BUFFERSIZE, strDecryBuffer, nLen, pKey, DESKEYLENGTH);
                strDecryBuffer[BUFFERSIZE - 1] = 0;
                if (strDecryBuffer[0] != 0 && strDecryBuffer[0] != '\n')
                {
                    printf("Receive message form<%s>: %s", pRemoteName, strDecryBuffer);
                    if (0 == memcmp("quit", strDecryBuffer, 4))
                    {
                        printf("Quit!\n");
                        break;
                    }
                }
            }
        }
        //判断标准输入是否有io操作
        if (FD_ISSET(0, &cHandleSet))
        {
            bzero(&strStdinBuffer, BUFFERSIZE);
            while (strStdinBuffer[0] == 0)
            {
                if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL)
                {
                    continue;
                }
            }
            int nLen = BUFFERSIZE;
            //加密并发送数据
            cDes.Encry(strStdinBuffer, BUFFERSIZE, strEncryBuffer, nLen, pKey, DESKEYLENGTH);
            if (send(nSock, strEncryBuffer, BUFFERSIZE, 0) != BUFFERSIZE)
            {
                perror("send");
            }
            else
            {
                if (0 == memcmp("quit", strStdinBuffer, 4))
                {
                    printf("Quit!\n");
                    break;
                }
            }
        }
    }
}

int main(int argc, char *args[])
{
    srand((unsigned)time(NULL));
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
        //初始化本地套接字
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
            printf("Connect Success!  \n");
            //生成DES密钥
            GerenateDesKey(strDesKey);
            printf("Create DES key success\n");
            //接收服务器出来的RSA公钥
            if (sizeof(cRsaPublicKey) == TotalRecv(nConnectSocket, (char *)&cRsaPublicKey,
                                                   sizeof(cRsaPublicKey), 0))
            {
                printf("Successful get the RSA public Key\n");
            }
            else
            {
                perror("Get RSA public key ");
                exit(0);
            }
            //使用RSA公钥加密DES密钥
            ULONG64 nEncryptDesKey[DESKEYLENGTH / 2];
            unsigned short *pDesKey = (unsigned short *)strDesKey;
            for (int i = 0; i < DESKEYLENGTH / 2; i++)
            {
                nEncryptDesKey[i] = CRSASection::Encry(pDesKey[i], cRsaPublicKey);
            }
            //发送加密后的DES密钥
            if (sizeof(ULONG64) * DESKEYLENGTH / 2 != send(nConnectSocket, (char *)nEncryptDesKey,
                                                                    sizeof(ULONG64) * DESKEYLENGTH / 2, 0))
            {
                perror("Send DES key Error");
                exit(0);
            }
            else
            {
                printf("Successful send the encrypted DES Key\n");
            }
            printf("Begin to chat...\n");
            SecretChat(nConnectSocket, strIpAddr, strDesKey);
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

        //初始化本地 sockaddr_in 结构体
        bzero(&sLocalAddr, sizeof(sLocalAddr));
        sLocalAddr.sin_family = PF_INET;
        sLocalAddr.sin_port = htons(SERVERPORT);
        sLocalAddr.sin_addr.s_addr = INADDR_ANY;

        //绑定本地套接字
        if (bind(nListenSocket, (struct sockaddr *)&sLocalAddr, sizeof(struct sockaddr)) == -1)
        {
            perror("bind");
            exit(1);
        }
        
        //开始监听
        if (listen(nListenSocket, 5) == -1)
        {
            perror("listen");
            exit(1);
        }
        printf("Listening...\n");
        nLength = sizeof(struct sockaddr);
        //和客户端建立连接
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
            CRSASection cRsaSection;
            cRsaPublicKey = cRsaSection.GetPublicKey();
            //向客户端发送RSA公钥
            if (send(nAcceptSocket, (char *)(&cRsaPublicKey), sizeof(cRsaPublicKey), 0) != sizeof(cRsaPublicKey))
            {
                perror("send");
                exit(0);
            }
            else
            {
                printf("successful send the RSA public key. \n");
            }
            //接收加密后的DES密钥并解密
            ULONG64 nEncryptDesKey[DESKEYLENGTH / 2];
            if (DESKEYLENGTH / 2 * sizeof(ULONG64) !=
                TotalRecv(nAcceptSocket, (char *)nEncryptDesKey, DESKEYLENGTH / 2 * sizeof(ULONG64), 0))
            {
                perror("TotalRecv DES key error");
                exit(0);
            }
            else
            {
                printf("successful get the DES key. \n");
                unsigned short *pDesKey = (unsigned short *)strDesKey;
                for (int i = 0; i < DESKEYLENGTH / 2; i++)
                {
                    pDesKey[i] = cRsaSection.Decry(nEncryptDesKey[i]);
                }
            }
            printf("Begin to chat...\n");
            SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), strDesKey);
            close(nAcceptSocket);
        }
    }
    return 0;
}