#ifndef LBCRYPTO_CRYPTO_RGSWOPS_H
#define LBCRYPTO_CRYPTO_RGSWOPS_H

//Includes Section
#include "palisade.h"
#include "ringgsw.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <class Element>
using GridCipherTypeBV = std::vector<std::shared_ptr<LWEForm<Element>>>;

template <class Element>
using GridCipherTypeGSW = std::vector<std::shared_ptr<RGSWCiphertext<Element>>>;

template <class Element>
class RGSWOps{
	public:
	static std::vector<std::shared_ptr<RGSWCiphertext<Element>>> circularKey;
	RGSWOps();
	static RGSWKeyPair<Element> KeyGen(const shared_ptr<LPCryptoParameters<Element>> cryptoParams);
	static std::shared_ptr<RGSWCiphertext<Element>> Encrypt(const RGSWPublicKey<Element> &pk, Element &m);
	static std::shared_ptr<RGSWCiphertext<Element>> Encrypt(const RGSWPublicKey<Element> &pk, uint64_t m);
	static std::shared_ptr<RGSWCiphertext<Element>> BootEncrypt(const RGSWPublicKey<Element> &pk, Element &m);
	static std::shared_ptr<RGSWCiphertext<Element>> ClearEncrypt(const RGSWPublicKey<Element> &pk, Element &m);
	static std::shared_ptr<RGSWCiphertext<Element>> ClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, Element &m);
	static std::shared_ptr<RGSWCiphertext<Element>> ClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, uint64_t m);
	static Element Decrypt(const std::shared_ptr<RGSWCiphertext<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk);
	static Element Decrypt(const std::shared_ptr<LWEForm<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk);

	static std::shared_ptr<RGSWCiphertext<Element>> Add(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b);
	static std::shared_ptr<LWEForm<Element>> Add(const std::shared_ptr<LWEForm<Element>> a,const std::shared_ptr<LWEForm<Element>> b);

	//b += a
	static void AddInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a, std::shared_ptr<RGSWCiphertext<Element>> b);
	static void AddInPlaceBV(const std::vector<shared_ptr<LWEForm<Element>>> a, std::vector<shared_ptr<LWEForm<Element>>> b);
	static void AddOneInPlace(std::shared_ptr<RGSWCiphertext<Element>> a);

	//result = a - b
	static std::shared_ptr<RGSWCiphertext<Element>> Subtract(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b);
	//b -= a
	static void SubtractInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b);

	static std::shared_ptr<RGSWCiphertext<Element>> ClearRingMultiply(const Element &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static void ClearRingMultiplyInPlace(const Element &a, shared_ptr<RGSWCiphertext<Element>> cipher);
	static void ClearRingMultiplyInPlace(const Element &a, shared_ptr<LWEForm<Element>> cipher);
	static void ClearRingMultiplyInPlace(const Element &a, GridCipherTypeGSW<Element> &cipher);
	static void ClearRingMultiplyInPlace(const Element &a, GridCipherTypeBV<Element> &cipher);
	static std::shared_ptr<RGSWCiphertext<Element>> Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<RGSWCiphertext<Element>> b);
	static std::shared_ptr<LWEForm<Element>> Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<LWEForm<Element>> b);
	static void MultiplyInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a, std::shared_ptr<LWEForm<Element>> b);
	static std::shared_ptr<RGSWCiphertext<Element>> ScalarMultiply(const typename Element::Integer &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static std::vector<shared_ptr<LWEForm<Element>>> ScalarMultiplyBV(const typename Element::Integer &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static std::shared_ptr<RGSWKeySwitchMatrix<Element>> KeySwitchGen(const std::shared_ptr<RGSWSecretKey<Element>> oldSk,const std::shared_ptr<RGSWSecretKey<Element>> newSk);
	static std::shared_ptr<RGSWCiphertext<Element>> KeySwitchGenBV(const std::shared_ptr<RGSWSecretKey<Element>> oldSk,const std::shared_ptr<RGSWSecretKey<Element>> newSk);

	static std::shared_ptr<RGSWCiphertext<Element>> KeySwitch(const std::shared_ptr<RGSWCiphertext<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey);
	static std::shared_ptr<LWEForm<Element>> KeySwitchUpper(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey);
	static std::shared_ptr<LWEForm<Element>> KeySwitchLower(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey);
	static std::shared_ptr<RGSWCiphertext<Element>> KeySwitchLeanRGSW(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey);
	static std::shared_ptr<LWEForm<Element>> KeySwitchBV(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWCiphertext<Element>> evalKey);

	static void ModReduce(std::shared_ptr<LWEForm<Element>> cipher, const typename Element::Integer &q, const shared_ptr<LPCryptoParameters<Element>> cryptoParams);

	static void SetOneCipher(const shared_ptr<LPCryptoParameters<Element>> cryptoParams);
	static void InitializeCircularKey(const RGSWKeyPair<Element> &kp);
	static void InitializeMaskKey(const RGSWKeyPair<Element> &kp);
	static void InitializeMaskKeyBV(const RGSWKeyPair<Element> &kp);
	static std::shared_ptr<RGSWCiphertext<Element>> ExtractMaskedCipher(std::shared_ptr<LWEForm<Element>> cipher);
	static std::shared_ptr<RGSWCiphertext<Element>> ExtractMaskedCipherAlt(std::shared_ptr<LWEForm<Element>> cipher);
	static std::shared_ptr<RGSWCiphertext<Element>> ExtractMaskedCipherAltAlt(std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static std::shared_ptr<LWEForm<Element>> ExtractMaskedCipherAltAlt(std::shared_ptr<LWEForm<Element>> cipher);

	static std::shared_ptr<RGSWKeySwitchMatrix<Element>> BootStrapKeySwitchGen(const std::shared_ptr<RGSWSecretKey<Element>> sk, const NativeVector &lweSK);
	static std::shared_ptr<RGSWCiphertext<Element>> BootStrapKeySwitchGenBV(const std::shared_ptr<RGSWSecretKey<Element>> sk, const NativeVector &lweSK);

	//Gridstrapping related functions
	static GridCipherTypeGSW<Element> GridCipherGSWClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, std::vector<Element> &m);
	static GridCipherTypeBV<Element> GridCipherBVClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, std::vector<Element> &m);
	//static std::shared_ptr<RGSWCiphertext<Element>> ExtractSign(const std::shared_ptr<LWEForm<Element>> cipher, const shared_ptr<LPCryptoParameters<Element>> cryptoParams);
	static std::shared_ptr<RGSWCiphertext<Element>> ExtractCarryOver(std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static void InitializeStaticVariables(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, usint gridSize, const NativeInteger &qLWE);
	static void GeneratePowerCache(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, usint ell);


	//Automorphism operation
	static std::shared_ptr<RGSWCiphertext<Element>> Automorph(const std::shared_ptr<RGSWCiphertext<Element>> cipher, usint morphIdx);
	static std::shared_ptr<LWEForm<Element>> Automorph(const std::shared_ptr<LWEForm<Element>> cipher, usint morphIdx);
	static Element Automorph(const Element &a, usint morphIdx);
	static shared_ptr<RGSWSecretKey<Element>> GetMorphedSecretkey(const shared_ptr<RGSWSecretKey<Element>> sk, usint morphIdx);

	//private:
	public:
	static shared_ptr<RGSWCiphertext<Element>> oneCipher;
	static shared_ptr<Element> oneMinusX;
	static shared_ptr<RGSWCiphertext<Element>> onePlusX;
	static std::vector<std::shared_ptr<RGSWKeySwitchMatrix<Element>>> maskKeysGSW;
	static std::vector<std::shared_ptr<RGSWCiphertext<Element>>> maskKeysBV;
	static shared_ptr<RGSWCiphertext<Element>> logNInverseCipher;
	static std::vector<shared_ptr<RGSWCiphertext<Element>>> rgswPowerCache;

};


}

#endif
