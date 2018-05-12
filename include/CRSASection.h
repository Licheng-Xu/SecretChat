#ifndef _CRSASECTION_H_
#define _CRSASECTION_H_


typedef unsigned long ULONG64;

struct PublicKey
{
    ULONG64 nE;
    ULONG64 nN;
};

struct RsaParam
{
    ULONG64 p; //16位随机素数
    ULONG64 q; //16位随即素数
    ULONG64 n; //p*q
    ULONG64 f; //φ(n)
    ULONG64 e; //1 < e < φ(n)
    ULONG64 d; //ed ≡ 1 (mod φ(n))
    ULONG64 s; //n的位数
};

//模乘运算
inline ULONG64 MulMod(ULONG64 a, ULONG64 b, ULONG64 n);
//模幂运算
ULONG64 PowMod(ULONG64 base, ULONG64 pow, ULONG64 n);
//质数判别函数
long RabinMillerKnl(ULONG64 &n);
//重复调用Rabin-Miller进行质数判别
long RabinMiller(ULONG64 &n, long loop);
//生成随机大质数
ULONG64 RandomPrime(char bits);
//辗转相除法求最大公约数
ULONG64 Gcd(ULONG64 &p, ULONG64 &q);
//生成私钥
ULONG64 Euclid(ULONG64 e, ULONG64 t_n);
//生成公钥私钥
RsaParam RsaGetParam(void);

class CRSASection
{
  private:
    RsaParam m_cParament;

  public:
    CRSASection();
    ~CRSASection();
    //加密函数
    static ULONG64 Encry(unsigned short nSorce, PublicKey &cKey);
    //解密函数
    unsigned short Decry(ULONG64 nScore);
    //公钥获取函数
    PublicKey GetPublicKey();
};

#endif