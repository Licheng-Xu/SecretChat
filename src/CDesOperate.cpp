#include "CDesOperate.h"

CDesOperate::CDesOperate()
{
	for (int i = 0; i < 16; i++)
	{
		for (int j = 0; j < 2; j++)
		{
			m_arrOutKey[i][j] = 0;
		}
	}
	for (int i = 0; i < 2; i++)
	{
		m_arrBufKey[i] = 0;
	}
}

INT32 CDesOperate::MakeFirstKey(ULONG32 *keyP)
{
	ULONG32 tempKey[2] = {0};
	ULONG32 *pFirstKey = (ULONG32 *)m_arrBufKey;
	ULONG32 *pTempKey = (ULONG32 *)tempKey;
	memset((ULONG8 *)m_arrBufKey, 0, sizeof(m_arrBufKey));
	memcpy((ULONG8 *)&tempKey, (ULONG8 *)keyP, 8);
	memset((ULONG8 *)m_arrOutKey, 0, sizeof(m_arrOutKey));
	int j = 0;
	for (j = 0; j < 28; j++)
	{ //循环28次   64---->56     但还是要用2个32位来存储
		if (keyleft[j] > 32)
		{ //第一个32位
			if (pTempKey[1] & pc_by_bit[keyleft[j] - 1])
			{								  //第一次出现这种pc_by_bit[],此后涉及到选取特定的位都将用到
				pFirstKey[0] |= pc_by_bit[j]; //其实原理很简单  先判断一下要选取的bit数组对应的位是否为1
			}								  //通过与上0x80000000(1000 0000 0000 0000...)等只有一bit为1的数即可判断
		}									  //再将相应的位置1通过或上0x80000000(1000 0000 0000 0000...)等只有一bit为1的数即可
		else
		{
			if (pTempKey[0] & pc_by_bit[keyleft[j] - 1])
			{
				pFirstKey[0] |= pc_by_bit[j];
			}
		}
		if (keyright[j] > 32)
		{ //第二个32位
			if (pTempKey[1] & pc_by_bit[keyright[j] - 1])
			{
				pFirstKey[1] |= pc_by_bit[j];
			}
		}
		else
		{
			if (pTempKey[0] & pc_by_bit[keyright[j] - 1])
			{
				pFirstKey[1] |= pc_by_bit[j];
			}
		}
	}
	for (j = 0; j < 16; j++)
	{
		MakeKey(&pFirstKey[0], &pFirstKey[1], j); //firstKey已形成，循环调用oneStepOfMakeSubKe()形成子秘钥
	}
	return 1;
}

INT32 CDesOperate::MakeKey(ULONG32 *keyleft, ULONG32 *keyright, ULONG32 number)
{
	ULONG32 tempKey[2] = {0, 0};
	ULONG32 *pTempKey = (ULONG32 *)tempKey;
	ULONG32 *pSubKey = (ULONG32 *)m_arrOutKey[number];
	ULONG32 helpData[3] = {0x0, 0x80000000, 0xc0000000}; //辅助数据,通过与上它们可以得到相应数据的最高位,待会有奇用
	pTempKey[0] = *keyleft & helpData[lefttable[number]];
	pTempKey[1] = *keyright & helpData[lefttable[number]];
	if (lefttable[number] == 1)
	{						//注意要达到循环左移的效果,没有相应的操作,只有先将其最高位保存下来，在想办法将其移到低位上去
		pTempKey[0] >>= 27; //具体实现：
		pTempKey[1] >>= 27; //与0xc0000000(110000000...高位为1)等数据相与得到高位(其他位被置0)
	}
	else
	{						//相与后的数据右移 将高位移到低位   由于只有28位 移26或27位即可，不必移30或31位
		pTempKey[0] >>= 26; //至此 最高位被移到了最低位(相对于28位) 接下来与左移的数据相或即可
		pTempKey[1] >>= 26;
	}
	pTempKey[0] &= 0xfffffff0; //本来只有28位却必须用32位存储,直接将低4位清0即可
	pTempKey[1] &= 0xfffffff0;
	*keyleft <<= lefttable[number]; // 左移
	*keyright <<= lefttable[number];
	*keyleft |= pTempKey[0]; //相或
	*keyright |= pTempKey[1];
	pTempKey[0] = 0;
	pTempKey[1] = 0; //至此循环左移结束 接下来56-->48

	int j = 0;
	for (; j < 48; j++)
	{
		if (j < 24)
		{
			if (*keyleft & pc_by_bit[keychoose[j] - 1])
			{
				pSubKey[0] |= pc_by_bit[j];
			}
		}
		else
		{
			if (*keyright & pc_by_bit[keychoose[j] - 28])
			{
				pSubKey[1] |= pc_by_bit[j - 24];
			}
		}
	}
	return 1;
}

INT32 CDesOperate::MakeData(ULONG32 *left, ULONG32 *right, ULONG32 number)
{
	ULONG32 oldRight = *right;
	ULONG8 useBySBox[8] = {0};
	ULONG32 exdesP[2] = {0}; //用于存放拓展后的数据
							 //32---->48
	int j = 0;
	for (; j < 48; j++)
	{ //只对right做拓展
		if (j < 24)
		{
			if (*right & pc_by_bit[des_E[j] - 1])
			{
				exdesP[0] |= pc_by_bit[j];
			}
		}
		else
		{
			if (*right & pc_by_bit[des_E[j] - 1])
			{
				exdesP[1] |= pc_by_bit[j - 24];
			}
		}
	}
	for (j = 0; j < 2; j++)
	{
		exdesP[j] ^= m_arrOutKey[number][j]; //子秘钥参与的异或运算
	}
	//48------>32
	exdesP[1] >>= 8;								  //24位存放再32的,所以左移8位到最低位
	useBySBox[7] = (ULONG8)(exdesP[1] & 0x0000003fL); //与上00000...00111111  低6位全为1
	exdesP[1] >>= 6;								  //左移6位
	useBySBox[6] = (ULONG8)(exdesP[1] & 0x0000003fL);
	exdesP[1] >>= 6;
	useBySBox[5] = (ULONG8)(exdesP[1] & 0x0000003fL);
	exdesP[1] >>= 6;
	useBySBox[4] = (ULONG8)(exdesP[1] & 0x0000003fL);

	exdesP[0] >>= 8;
	useBySBox[3] = (ULONG8)(exdesP[0] & 0x0000003fL);
	exdesP[0] >>= 6;
	useBySBox[2] = (ULONG8)(exdesP[0] & 0x0000003fL);
	exdesP[0] >>= 6;
	useBySBox[1] = (ULONG8)(exdesP[0] & 0x0000003fL);
	exdesP[0] >>= 6;
	useBySBox[0] = (ULONG8)(exdesP[0] & 0x0000003fL);
	exdesP[0] = 0;
	exdesP[1] = 0; //至此数据被分为8组,每组6位(尽管必须用8位存储)
	*right = 0;
	for (j = 0; j < 7; j++)
	{ //查SBox表  6位变4位     即48---->32
		*right |= des_S[j][useBySBox[j]];
		*right <<= 4;
	}
	*right |= des_S[j][useBySBox[j]];
	ULONG32 tempData = 0;
	for (j = 0; j < 32; j++) //不必多说 换位
	{
		if (*right & pc_by_bit[des_P[j] - 1])
		{
			tempData |= pc_by_bit[j];
		}
	}
	*right = tempData;

	*right ^= *left; //传的是指针 ,用于迭代
	*left = oldRight;
	return 1;
}

INT32 CDesOperate::HandleData(ULONG32 *left, ULONG8 choice)
{
	int j = 0;
	ULONG32 *right = &left[1];
	ULONG32 tempData[2] = {0};
	for (j = 0; j < 64; j++)
	{
		if (j < 32)
		{
			if (pc_first[j] > 32)
			{
				if (*right & pc_by_bit[pc_first[j] - 1])
				{
					tempData[0] |= pc_by_bit[j];
				}
			}
			else
			{
				if (*left & pc_by_bit[pc_first[j] - 1])
				{
					tempData[0] |= pc_by_bit[j];
				}
			}
		}
		else
		{ //j>32
			if (pc_first[j] > 32)
			{
				if (*right & pc_by_bit[pc_first[j] - 1])
				{
					tempData[1] |= pc_by_bit[j];
				}
			}
			else
			{
				if (*left & pc_by_bit[pc_first[j] - 1])
				{
					tempData[1] |= pc_by_bit[j];
				}
			}
		}
	}
	*left = tempData[0];
	*right = tempData[1];
	tempData[0] = 0;
	tempData[1] = 0;
	int number = 0;
	switch (choice)
	{
	case 0: //加密
		for (number = 0; number < 16; number++)
		{
			MakeData(left, right, (ULONG32)number); //16轮迭代
		}
		break;
	case 1: //解密
		for (number = 15; number >= 0; number--)
		{
			MakeData(left, right, (ULONG32)number); //16轮迭代
		}
		break;
	default:
		break;
	}
	ULONG32 temp;
	temp = *left;
	*left = *right;
	*right = temp;
	for (j = 0; j < 64; j++)
	{
		if (j < 32)
		{
			if (pc_last[j] > 32) /*属于right*/
			{
				if (*right & pc_by_bit[pc_last[j] - 1])
				{
					tempData[0] |= pc_by_bit[j];
				}
			}
			else
			{
				if (*left & pc_by_bit[pc_last[j] - 1])
				{
					tempData[0] |= pc_by_bit[j];
				}
			}
		}
		else
		{
			if (pc_last[j] > 32) /*属于right*/
			{
				if (*right & pc_by_bit[pc_last[j] - 1])
				{
					tempData[1] |= pc_by_bit[j];
				}
			}
			else
			{
				if (*left & pc_by_bit[pc_last[j] - 1])
				{
					tempData[1] |= pc_by_bit[j];
				}
			}
		}
	}
	*left = tempData[0];
	*right = tempData[1];
	return 1;
}

INT32 CDesOperate::Encry(char *pPlaintext, int nPlaintextLength, char *pCipherBuffer, int &nCipherBufferLength, char *pKey, int nKeyLength)
{
	if (nKeyLength != 8)
    {
        return 0;
    }
    MakeFirstKey((ULONG32 *)pKey);
    int length = ((nPlaintextLength + 7) / 8) * 2; //length×4后肯定比原文长而且为64的整数倍
    if (nCipherBufferLength < length * 4)
    { //密文不够长
        nCipherBufferLength = length * 4;
    }
    memset(pCipherBuffer, 0, nCipherBufferLength); //密文置0
    ULONG32 *output = (ULONG32 *)pCipherBuffer;
    ULONG32 *source;
    if (nPlaintextLength != sizeof(ULONG32) * length) //确保明文64位对齐
    {
        source = new ULONG32[length];
        memset(source, 0, sizeof(ULONG32) * length);
        memcpy(source, pPlaintext, nPlaintextLength);
		//printf("%d\n---\n\n", sizeof(ULONG32));
    }
    else
    {
        source = (ULONG32 *)pPlaintext;
    }
    ULONG32 msg[2] = {0, 0};
    for (int i = 0; i < (length / 2); i++)
    {                           //每64位为一次加密
        msg[0] = source[2 * i]; //64位为两个long，2位进行一次加密，下同
        msg[1] = source[2 * i + 1];
        HandleData(msg, (ULONG8)0); //加密
        output[2 * i] = msg[0];     //得到密文
        output[2 * i + 1] = msg[1];
    }
    if (pPlaintext != (char *)source)
    {
        delete[] source;
    }
    return 1;
}

INT32 CDesOperate::Decry(char *pCipher, int nCipherBufferLength, char *pPlaintextBuffer, int &nPlaintextBufferLength, char *pKey, int nKeyLength)
{
	if (nKeyLength != 8)
    {
        return 0;
    }
	if (nCipherBufferLength % 8 != 0)
    {
        return 0;
    }
    if (nPlaintextBufferLength < nCipherBufferLength) //与加密过程类似,不必多说
    {
        nPlaintextBufferLength = nCipherBufferLength;
        return 0;
    }
    MakeFirstKey((ULONG32 *)pKey);
    memset(pPlaintextBuffer, 0, nPlaintextBufferLength);
    ULONG32 *pSouce = (ULONG32 *)pCipher;
    ULONG32 *pDest = (ULONG32 *)pPlaintextBuffer;
    ULONG32 gp_msg[2] = {0, 0};
    for (int i = 0; i < (nCipherBufferLength / 8); i++)
    {
        gp_msg[0] = pSouce[2 * i];
        gp_msg[1] = pSouce[2 * i + 1];
        HandleData(gp_msg, (ULONG8)1);
        pDest[2 * i] = gp_msg[0];
        pDest[2 * i + 1] = gp_msg[1];
    }
    return 1;
}

