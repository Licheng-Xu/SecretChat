#ifndef _CRSASECTION_H_
#define _CRSASECTION_H_


#define __int64 long

struct PublicKey
{
    unsigned __int64 nE;
    unsigned __int64 nN;
};

struct RsaParam
{
    unsigned __int64 p; //随机素数
    unsigned __int64 q; //随即素数
    unsigned __int64 n; //
    unsigned __int64 f;
    unsigned __int64 e;
    unsigned __int64 d;
    unsigned __int64 s;
};

//模乘运算
inline unsigned __int64 MulMod(unsigned __int64 a, unsigned __int64 b, unsigned __int64 n);
//模幂运算
unsigned __int64 PowMod(unsigned __int64 base, unsigned __int64 pow, unsigned __int64 n);
//质数判别函数
long RabinMillerKnl(unsigned __int64 &n);
//重复调用Rabin-Miller进行质数判别
long RabinMiller(unsigned __int64 &n, long loop);
//生成随机大质数
unsigned __int64 RandomPrime(char bits);
//辗转相除法求最大公约数
unsigned __int64 Gcd(unsigned __int64 &p, unsigned __int64 &q);
//生成私钥
unsigned __int64 Euclid(unsigned __int64 e, unsigned __int64 t_n);
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
    static unsigned __int64 Encry(unsigned short nSorce, PublicKey &cKey);
    //解密函数
    unsigned short Decry(unsigned __int64 nScore);
    //公钥获取函数
    PublicKey GetPublicKey();
};

#endif