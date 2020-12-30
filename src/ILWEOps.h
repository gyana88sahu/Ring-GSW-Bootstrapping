
#ifndef LBCRYPTO_CRYPTO_ILWEOPS_H
#define LBCRYPTO_CRYPTO_ILWEOPS_H

#include "integerlwedefs.h"

namespace lbcrypto{

class ILWEOps{
public:

	static ILWEKeyPair KeyGen(const shared_ptr<ILWEParams> &param);

	static shared_ptr<ILWECiphertext> Encrypt(const ILWEPublicKey &pk, usint m);

	static usint Decrypt(const shared_ptr<ILWECiphertext> cipher, const ILWESecretKey &sk);

	static void KeySwitchGen(const ILWESecretKey &sk);

	static shared_ptr<ILWECiphertext> EvalNand(const shared_ptr<ILWECiphertext> c1, const shared_ptr<ILWECiphertext> c2);

};

}
#endif
