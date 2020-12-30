#ifndef LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_H
#define LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_H

#include "integerlwedefs.h"
#include "ringgsw.h"
#include "RingGSWOPS.h"

namespace lbcrypto{

class ISLWEOps{
public:

	static ILWEKeyPair KeyGen(const shared_ptr<ILWEParams> &param, string gen="TERNARY");

	static shared_ptr<ILWECiphertext> Encrypt(const ILWEPublicKey &pk, usint m);

	static usint Decrypt(const shared_ptr<ILWECiphertext> cipher, const ILWESecretKey &sk);

	static std::vector<std::vector<shared_ptr<ILWECiphertext>>> KeySwitchGen(const ILWESecretKey &sk,const ILWESecretKey &newSk,usint rKS);

	static shared_ptr<ILWECiphertext> KeySwitch(const shared_ptr<ILWECiphertext> cipher, const std::vector<std::vector<ILWECiphertext>> &hint);

	static shared_ptr<ILWECiphertext> EvalMult(const shared_ptr<ILWECiphertext> c1, const shared_ptr<ILWECiphertext> c2);

	static shared_ptr<ILWECiphertext> ModSwitch(shared_ptr<ILWECiphertext> c, NativeInteger &qDash);

	template <class Element>
	static std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> BootstrappingKeyGen(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk);

	template <class Element>
	static std::vector<std::shared_ptr<RGSWCiphertext<Element>>> BootstrappingKeyGenBinary(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk);

	template <class Element>
	static std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> BootstrappingKeyGenAuto(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk);
};

}

#endif
