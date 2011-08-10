#ifndef SRPLIB_H_
#define SRPLIB_H_

#include <memory.h>
#include <assert.h>

extern "C"
{
#include "..\thirdparty\miracl\miracl.h"
}

namespace srplib
{
    template<int array_size>
    class ByteArray
    {
    public:
        ByteArray()
        {
            memset(value_, 0 , sizeof(value_));
        }

        const char * value() const
        {
            return value_;
        }

        void set_value(const char * value, int size)
        {
            if(size > sizeof(value_))
                memcpy(value_, value, sizeof(value_));
            else
                memcpy(value_, value, size);
        }

        char & operator[](const int index)
        {
            assert(index < sizeof(value_));
            return value_[index];
        }

        operator char *()
        {
            return value_;
        }

        operator const char *() const
        {
            return value_;
        }

        bool operator==(const ByteArray<array_size> & obj)
        {
            return memcmp(value_, obj.value_, array_size) == 0;
        }
    private:
        char value_[array_size];
    };

    typedef ByteArray<32> SRPHash;
    typedef ByteArray<256> SRPBigNumber;
    typedef ByteArray<8> SRPSalt;

    class SRPBase
    {
    protected:
        static big big_n_;
        static big g_;
        static big k_;
        static char big_n_buffer_[mr_big_reserve(1,256)];
        static char g_buffer_[mr_big_reserve(1,256)];
        static char k_buffer_[mr_big_reserve(1,256)];
        static csprng rngctx_;
    protected:
        static const int kMaxUserName = 128; // in bytes.
    public:
        /*
        Invoke this method before use any others.
        It will set up parameters use by whole procedure.
        Usually, it invoked at very beginning of your application.
        */
        static bool SRPInit(
            const SRPBigNumber & big_n,
            const SRPBigNumber & g);

        /*
        When you not need SRPLib any more. Invoked this to do clean up work.
        */
        static void SRPExit();

        /*
        Generate salt and calc verifier. Use in register procedure.
        */
        static bool GenerateSaltAndVerifier(
            const char * pwd,
            const int size_pwd,
            SRPSalt & salt,
            SRPBigNumber & verifier);

    public:
        SRPBase();
        virtual ~SRPBase();

        bool init();
        void fini();

        /*
        Calc the intermedia key.
        */
        void CalcIntermediaKey();

        /*
        Shared key accessor.
        */
        SRPHash * GetSharedKey();

    protected:
        big big_a_;
        big salt_;
        big big_b_;
        big u_;
        char big_a_buffer_[mr_big_reserve(1,256)];
        char salt_buffer_[mr_big_reserve(1,256)];
        char big_b_buffer_[mr_big_reserve(1,256)];
        char u_buffer_[mr_big_reserve(1,256)];
        SRPHash shared_key_;
        miracl mir_;
    };

    class SRPClient:
        public SRPBase
    {
    public:
        SRPClient();
        ~SRPClient();

        /*
        After construct a SRPClient object.
        Init should invoke before other method.
        */
        bool init();

        void fini();

        /*
        Generate a big number relate to the random number a_.
        It should communicate with server.
        */
        bool GetA(SRPBigNumber & big_a);

        /*
        Server will response with a salt and a big number which relate to server-side random  number b_.
        Client should know them.
        */
        bool Prepare(const SRPSalt & salt,
            const SRPBigNumber & big_b);

        /*
        To keep consistent with server, We should strore password when client initialize.
        But we don't do that, because we want to minimize the duration which plain password appear in memory.
        */
        void CalcSharedKey(char * pwd, int size_pwd, SRPHash & hash_saltedpwd);

        /*
        In some case, authorization will done by hash instead of plain password.
        */
        void CalcSharedKey(const SRPHash & hash_saltedpwd);

        /*
        Show this key to server to proof the shared key are exactly same.
        More information include in hash, harder to guess original shared key.
        */
        bool GetProofKey(SRPHash & key);

        /*
        Server will show you proof key too. Verify it by this method.
        Return true if everything is ok.otherwise false.
        */
        bool VerifyKey(const SRPHash & key);

        /*
        internal use when verify key.
        */
        bool GetProofKeyM2(SRPHash & key);

    private:
        big a_;
        char a_buffer_[mr_big_reserve(1,256)];
    };

    class SRPServer:
        public SRPBase
    {
    public:
        SRPServer();
        ~SRPServer();

        /*
        Invoke this method first before any others.
        */
        bool init(const SRPSalt & salt,
            const SRPBigNumber & verifier);

        void fini();

        bool GetB(SRPBigNumber & big_b);

        bool Prepare(const SRPBigNumber & big_a);

        void CalcSharedKey();

        bool GetProofKey(const SRPHash & c, SRPHash & key);

        bool VerifyKey(const SRPHash & key);

        bool GetProofKeyM1(SRPHash & key);
    private:
        big b_;
        big v_;
        char b_buffer_[mr_big_reserve(1,256)];
        char v_buffer_[mr_big_reserve(1,256)];
    };
}


#endif