#include "srplib.h"

#include <stdlib.h>
#include <memory.h>
#include <time.h>

namespace srplib
{


///////////////////////////static member define start//////////////////////////
big SRPBase::big_n_ = 0;
big SRPBase::g_ = 0;
big SRPBase::k_ = 0;
char SRPBase::big_n_buffer_[mr_big_reserve(1,256)] = {0};
char SRPBase::g_buffer_[mr_big_reserve(1,256)] = {0};
char SRPBase::k_buffer_[mr_big_reserve(1,256)] = {0};
csprng SRPBase::rngctx_;
//////////////////////////static member define end/////////////////////////////

///////////////////////SRPBase static method define start//////////////////////

bool SRPBase::SRPInit(
    const SRPBigNumber & big_n,
    const SRPBigNumber & g)
{
    sha256 hashctx;
    miracl mir;
    SRPHash k_hash;
    int seed = static_cast<int>(time(0));

    if(mirsys(&mir, 512, 256) != &mir)
        return false;

    srand(seed);
    for(int i = 0; 
        i < sizeof(k_hash);
        ++i)
    {
        k_hash[i] = static_cast<char>(rand());
    }

    strong_init(&rngctx_,sizeof(k_hash), k_hash, seed);

    big_n_ = mirvar_mem(&mir,big_n_buffer_,0);
    g_ = mirvar_mem(&mir,g_buffer_,0);
    k_ = mirvar_mem(&mir,k_buffer_,0);

    bytes_to_big(&mir, sizeof(big_n), big_n, big_n_);
    bytes_to_big(&mir, sizeof(g), g, g_);

    shs256_init(&hashctx);
    for(int i = 0 ; i < sizeof(big_n); ++i)
        shs256_process(&hashctx, big_n[i]);
    for(int i = 0 ; i < sizeof(g); ++i)
        shs256_process(&hashctx, g[i]);
    shs256_hash(&hashctx, k_hash);

    bytes_to_big(&mir, sizeof(k_hash), k_hash, k_);

    mirexit(&mir);

    return true;
}

void SRPBase::SRPExit()
{
    strong_kill(&rngctx_);
}

bool SRPBase::GenerateSaltAndVerifier(
    const char * pwd,
    const int size_pwd,
    SRPSalt & salt,
    SRPBigNumber & verifier)
{
    miracl mir;
    SRPHash hash_sp;
    char sxv_buffer[mr_big_reserve(3,256)] = {0};

    if(mirsys(&mir, 512, 256) != &mir)
        return false;

    //prepare_monty(mir, big_n_);

    big s = mirvar_mem(&mir, sxv_buffer, 0);
    big x = mirvar_mem(&mir, sxv_buffer, 1);
    big v = mirvar_mem(&mir, sxv_buffer, 2);

    //generate salt
    strong_bigdig(&mir, &rngctx_, 64, 2, s);
    big_to_bytes(&mir, 8, s, salt, TRUE);

    //generate hash
    sha256 hashctx;
    shs256_init(&hashctx);

    for(int i = 0; i < sizeof(salt); ++i)
        shs256_process(&hashctx, salt[i]);
    for(int i = 0; i < size_pwd; ++i)
        shs256_process(&hashctx, pwd[i]);

    shs256_hash(&hashctx, hash_sp);
    bytes_to_big(&mir, sizeof(hash_sp), hash_sp, x);

    //calc verifier
    powmod(&mir, g_, x, big_n_, v);
    big_to_bytes(&mir, sizeof(verifier), v, verifier, TRUE);

    mirexit(&mir);
    return true;
}

///////////////////////SRPBase static method define end////////////////////////

///////////////////////SRPBase method define start/////////////////////////////
SRPBase::SRPBase()
    :big_a_(0),
     salt_(0),
     big_b_(0),
     u_(0),
     shared_key_()
{
    memset(big_a_buffer_, 0, sizeof(big_a_buffer_));
    memset(salt_buffer_, 0, sizeof(salt_buffer_));
    memset(big_b_buffer_, 0, sizeof(big_b_buffer_));
    memset(u_buffer_, 0, sizeof(u_buffer_));
    memset(&mir_, 0 ,sizeof(mir_));
}

SRPBase::~SRPBase()
{
    fini();
}

bool SRPBase::init()
{
    if(mirsys(&mir_, 512, 256) != &mir_)
        return false;

    big_a_ = mirvar_mem(&mir_, big_a_buffer_, 0);
    big_b_ = mirvar_mem(&mir_, big_b_buffer_, 0);
    salt_ = mirvar_mem(&mir_, salt_buffer_, 0);
    u_ = mirvar_mem(&mir_, u_buffer_, 0);
    return true;
}

void SRPBase::fini()
{
    if(&mir_)
    {
        mirexit(&mir_);
    }
}

void SRPBase::CalcIntermediaKey()
{
    SRPBigNumber big_a;
    SRPBigNumber big_b;
    SRPHash u;
    sha256 hashctx;

    big_to_bytes(&mir_, sizeof(big_a), big_a_, big_a, TRUE);
    big_to_bytes(&mir_, sizeof(big_b), big_b_, big_b, TRUE);

    shs256_init(&hashctx);
    for(unsigned int i = 0 ; i < sizeof(big_a); ++i)
        shs256_process(&hashctx, big_a[i]);
    for(unsigned int i = 0 ; i < sizeof(big_b); ++i)
        shs256_process(&hashctx, big_b[i]);
    shs256_hash(&hashctx, u);
    //calc u
    bytes_to_big(&mir_, sizeof(u), u, u_);
    return;
}

SRPHash * SRPBase::GetSharedKey()
{
    return &shared_key_;
}

///////////////////////SRPBase method define start/////////////////////////////

///////////////////////////////SRPClient start/////////////////////////////////
SRPClient::SRPClient()
    :a_(0)
{
    memset(a_buffer_, 0, sizeof(a_buffer_));
}

SRPClient::~SRPClient()
{
    fini();
}

bool SRPClient::init()
{
    if(!SRPBase::init())
        return false;

    a_ = mirvar_mem(&mir_, a_buffer_, 0);
    strong_bigdig(&mir_, &rngctx_, 2048, 2, a_);
    return true;
}

void SRPClient::fini()
{
}

bool SRPClient::GetA(SRPBigNumber & big_a)
{
    powmod(&mir_, g_, a_, big_n_, big_a_);
    big_to_bytes(&mir_, sizeof(big_a), 
        big_a_, big_a, TRUE);
    return true;
}

bool SRPClient::Prepare(const SRPSalt & salt,
            const SRPBigNumber & big_b)
{
    bytes_to_big(&mir_, sizeof(salt), salt, salt_);
    bytes_to_big(&mir_,sizeof(big_b), big_b, big_b_);
    if(divisible(&mir_, big_n_, big_b_))
        return false;
    else
        return true;
}

void SRPClient::CalcSharedKey(char * pwd, int size_pwd, SRPHash & hash_saltedpwd)
{
    SRPSalt salt;
    sha256 hashctx;
    SRPBigNumber sc;
    char temp_bignum_buffer[mr_big_reserve(4,256)] = {0};    //intermedia for calculation

    big temp_bignum_1 = mirvar_mem(&mir_, temp_bignum_buffer, 0);
    big temp_bignum_2 = mirvar_mem(&mir_, temp_bignum_buffer, 1);
    big temp_bignum_3 = mirvar_mem(&mir_, temp_bignum_buffer, 2);
    big temp_bignum_4 = mirvar_mem(&mir_, temp_bignum_buffer, 3);

    big_to_bytes(&mir_, sizeof(salt), salt_, salt, TRUE);
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(salt); ++i)
        shs256_process(&hashctx, salt[i]);
    for(int i = 0; i < size_pwd; ++i)
        shs256_process(&hashctx, pwd[i]);

    shs256_hash(&hashctx, hash_saltedpwd);
    bytes_to_big(&mir_, sizeof(hash_saltedpwd), hash_saltedpwd, temp_bignum_1);

    //a+u*x
    multiply(&mir_, u_, temp_bignum_1, temp_bignum_2);
    add(&mir_, a_, temp_bignum_2, temp_bignum_4);

    //B-k*(g^x mod N)
    powmod(&mir_, g_, temp_bignum_1, big_n_, temp_bignum_2);
    multiply(&mir_, k_, temp_bignum_2, temp_bignum_1);
    subtract(&mir_, big_b_ , temp_bignum_1, temp_bignum_2);

    powmod(&mir_, temp_bignum_2, temp_bignum_4, big_n_, temp_bignum_3);

    big_to_bytes(&mir_, sizeof(sc), temp_bignum_3, sc, TRUE);

    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(sc); ++i)
        shs256_process(&hashctx, sc[i]);
    shs256_hash(&hashctx, shared_key_);
}

void SRPClient::CalcSharedKey(const SRPHash & hash_saltedpwd)
{
    sha256 hashctx;
    SRPBigNumber sc;
    char temp_bignum_buffer[mr_big_reserve(4,256)] = {0};    //intermedia for calculation

    big temp_bignum_1 = mirvar_mem(&mir_, temp_bignum_buffer, 0);
    big temp_bignum_2 = mirvar_mem(&mir_, temp_bignum_buffer, 1);
    big temp_bignum_3 = mirvar_mem(&mir_, temp_bignum_buffer, 2);
    big temp_bignum_4 = mirvar_mem(&mir_, temp_bignum_buffer, 3);

    bytes_to_big(&mir_, sizeof(hash_saltedpwd), 
        hash_saltedpwd, temp_bignum_1);

    //a+u*x
    multiply(&mir_, u_, temp_bignum_1, temp_bignum_2);
    add(&mir_, a_ , temp_bignum_2, temp_bignum_4);

    //B-k*(g^x mod N)
    powmod(&mir_, g_, temp_bignum_1, big_n_, temp_bignum_2);
    multiply(&mir_, k_, temp_bignum_2, temp_bignum_1);
    subtract(&mir_, big_b_, temp_bignum_1, temp_bignum_2);

    powmod(&mir_, temp_bignum_2, temp_bignum_4, big_n_, temp_bignum_3);

    big_to_bytes(&mir_, sizeof(sc), temp_bignum_3, sc, TRUE);

    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(sc); ++i)
        shs256_process(&hashctx, sc[i]);
    shs256_hash(&hashctx, shared_key_);
}

bool SRPClient::GetProofKey(SRPHash & key)
{
    SRPBigNumber big_n;
    SRPBigNumber big_a;
    SRPBigNumber big_b;
    SRPBigNumber g;
    SRPHash hash_big_n;
    SRPHash hash_g;
    SRPHash hash_big_n_xor_g;
    sha256 hashctx;
    SRPSalt salt;

    big_to_bytes(&mir_, sizeof(big_n), big_n_, big_n, TRUE);
    big_to_bytes(&mir_, sizeof(big_a), big_a_, big_a, TRUE);
    big_to_bytes(&mir_, sizeof(big_b), big_b_, big_b, TRUE);
    big_to_bytes(&mir_, sizeof(g), g_, g, TRUE);
    big_to_bytes(&mir_, sizeof(salt), salt_, salt, TRUE);
    
    //hash N
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(big_n); ++i)
        shs256_process(&hashctx, big_n[i]);
    shs256_hash(&hashctx, hash_big_n);

    //hash g
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(g); ++i)
        shs256_process(&hashctx, g[i]);
    shs256_hash(&hashctx, hash_g);

    //H(N) xor H(g)
    for(int i = 0; i < sizeof(hash_big_n_xor_g); ++i)
        hash_big_n_xor_g[i] = hash_big_n[i] ^ hash_g[i];

    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(hash_big_n_xor_g); ++i)
        shs256_process(&hashctx, hash_big_n_xor_g[i]);
    for(int i = 0; i < sizeof(salt); ++i)
        shs256_process(&hashctx, salt[i]);
    for(int i = 0; i < sizeof(big_a); ++i)
        shs256_process(&hashctx, big_a[i]);
    for(int i = 0; i < sizeof(big_b); ++i)
        shs256_process(&hashctx, big_b[i]);
    for(int i = 0; i < sizeof(shared_key_); ++i)
        shs256_process(&hashctx, shared_key_[i]);

    shs256_hash(&hashctx, key);
    return true;

}

bool SRPClient::VerifyKey(const SRPHash & key)
{
    SRPHash m2;
    if(!GetProofKeyM2(m2))
        return false;

    return m2 == key;
}

bool SRPClient::GetProofKeyM2(SRPHash & key)
{
    SRPBigNumber big_a;
    SRPHash mc;
    sha256 hashctx;

    big_to_bytes(&mir_, sizeof(big_a), big_a_, big_a, TRUE);

    if(!GetProofKey(mc))
        return false;

    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(big_a); ++i)
        shs256_process(&hashctx, big_a[i]);
    for(int i = 0; i < sizeof(mc); ++i)
        shs256_process(&hashctx, mc[i]);
    for(int i = 0; i < sizeof(shared_key_); ++i)
        shs256_process(&hashctx, shared_key_[i]);

    shs256_hash(&hashctx,key);
    return true;
}

///////////////////////////////SRPClient end///////////////////////////////////
//
///////////////////////////////SRPServer start/////////////////////////////////
SRPServer::SRPServer()
    :b_(0),
     v_(0)
{
    memset(b_buffer_, 0, sizeof(b_buffer_));
    memset(v_buffer_, 0, sizeof(v_buffer_));
}

SRPServer::~SRPServer()
{
    fini();
}

bool SRPServer::init(const SRPSalt & salt,
    const SRPBigNumber & verifier)
{
    if(!SRPBase::init())
        return false;

    b_ = mirvar_mem(&mir_, b_buffer_, 0);
    v_ = mirvar_mem(&mir_, v_buffer_, 0);

    bytes_to_big(&mir_, sizeof(verifier), verifier, v_);
    bytes_to_big(&mir_, sizeof(salt), salt, salt_);

    char temp_big_buffer[mr_big_reserve(3,256)] = {0};
    big kv = mirvar_mem(&mir_, temp_big_buffer,0);
    big gb = mirvar_mem(&mir_, temp_big_buffer,1);
    

    strong_bigdig(&mir_, &rngctx_, 2048, 2, b_);
    multiply(&mir_, k_, v_, kv);
    powmod(&mir_, g_, b_, big_n_, gb);
    add(&mir_, kv, gb, big_b_);
    divide(&mir_, big_b_, big_n_, big_n_);
    return true;
}

void SRPServer::fini()
{

}

bool SRPServer::GetB(SRPBigNumber & big_b)
{
    big_to_bytes(&mir_, sizeof(big_b), big_b_, big_b, TRUE);
    return true;
}

bool SRPServer::Prepare(const SRPBigNumber & big_a)
{
    bytes_to_big(&mir_, sizeof(big_a), big_a, big_a_);
    if(divisible(&mir_, big_n_, big_a_))
        return false;
    else
        return true;
}

void SRPServer::CalcSharedKey()
{
    char temp_bignum_buffer[mr_big_reserve(2,256)] = {0};    //intermedia for calculation

    big temp_bignum_1 = mirvar_mem(&mir_, temp_bignum_buffer, 0);
    big temp_bignum_2 = mirvar_mem(&mir_, temp_bignum_buffer, 1);

    SRPBigNumber ss;

    powmod(&mir_, v_, u_, big_n_, temp_bignum_1);
    multiply(&mir_, big_a_, temp_bignum_1, temp_bignum_2);
    powmod(&mir_, temp_bignum_2, b_, big_n_, temp_bignum_1);
    big_to_bytes(&mir_, sizeof(ss), temp_bignum_1, ss, TRUE);

    sha256 hashctx;
    shs256_init(&hashctx);
    for(int i = 0 ; i < sizeof(ss);i++)
        shs256_process(&hashctx, ss[i]);
    shs256_hash(&hashctx,shared_key_);
}

bool SRPServer::GetProofKey(
    const SRPHash & c,
    SRPHash & key)
{
    SRPBigNumber big_a;
    big_to_bytes(&mir_, sizeof(big_a), big_a_, big_a, TRUE);

    sha256 hashctx;
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(big_a); ++i)
        shs256_process(&hashctx, big_a[i]);
    for(int i = 0; i < sizeof(c); ++i)
        shs256_process(&hashctx, c[i]);
    for(int i = 0; i < sizeof(shared_key_); ++i)
        shs256_process(&hashctx, shared_key_[i]);
    shs256_hash(&hashctx,key);
    return true;
}

bool SRPServer::VerifyKey(const SRPHash & key)
{
    SRPHash c;
    if(!GetProofKeyM1(c))
        return false;

    return c == key;
}

bool SRPServer::GetProofKeyM1(SRPHash & key)
{
    SRPBigNumber big_n;
    SRPBigNumber big_a;
    SRPBigNumber big_b;
    SRPBigNumber g;
    SRPSalt salt;
    big_to_bytes(&mir_, sizeof(big_n), big_n_, big_n, TRUE);
    big_to_bytes(&mir_, sizeof(big_a), big_a_, big_a, TRUE);
    big_to_bytes(&mir_, sizeof(big_b), big_b_, big_b, TRUE);
    big_to_bytes(&mir_, sizeof(g), g_, g, TRUE);
    big_to_bytes(&mir_, sizeof(salt), salt_, salt, TRUE);

    SRPHash hash_big_n;
    SRPHash hash_g;
    SRPHash hash_big_n_xor_g;
    sha256 hashctx;
    //hash N
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(big_n); ++i)
        shs256_process(&hashctx, big_n[i]);
    shs256_hash(&hashctx,hash_big_n);
    //hash g
    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(g); ++i)
        shs256_process(&hashctx, g[i]);
    shs256_hash(&hashctx, hash_g);
    //H(N) xor H(g)
    for(int i = 0; i < sizeof(hash_big_n_xor_g); ++i)
        hash_big_n_xor_g[i]=hash_big_n[i] ^ hash_g[i];

    shs256_init(&hashctx);
    for(int i = 0; i < sizeof(hash_big_n_xor_g); ++i)
        shs256_process(&hashctx, hash_big_n_xor_g[i]);
    for(int i = 0; i < sizeof(salt); ++i)
        shs256_process(&hashctx, salt[i]);
    for(int i = 0; i < sizeof(big_a); ++i)
        shs256_process(&hashctx, big_a[i]);
    for(int i = 0; i < sizeof(big_b); ++i)
        shs256_process(&hashctx, big_b[i]);
    for(int i = 0; i < sizeof(shared_key_); ++i)
        shs256_process(&hashctx, shared_key_[i]);

    shs256_hash(&hashctx, key);
    return true;
}
///////////////////////////////SRPServer end///////////////////////////////////

}