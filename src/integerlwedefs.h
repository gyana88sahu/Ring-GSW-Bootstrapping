#ifndef LBCRYPTO_INTEGERLWE_H
#define LBCRYPTO_INTEGERLWE_H

#include "palisade.h"

namespace lbcrypto {


class ILWE{
private:
	NativeVector m_a;
	NativeInteger m_b;

public:
	ILWE(usint length,NativeInteger modulus);

	ILWE(const NativeVector& a, const NativeInteger &b);

	const NativeVector& GetA() const;

	void SetA(const NativeVector& a);

	void SetA(NativeVector &&a);

	const NativeInteger& GetB() const;

	void SetB(const NativeInteger& b);
};

class ILWEParams{
private:
	NativeInteger pMod;
	NativeInteger modulus;
	usint m_dim;
	shared_ptr<NativePoly::DugType> m_dug;
	shared_ptr<NativePoly::DggType> m_dgg;
	shared_ptr<NativePoly::TugType> m_tug;
	shared_ptr<NativePoly::BugType> m_bug;

public :
	ILWEParams(const NativeInteger p,const NativeInteger mod,usint dim);
	NativeInteger GetPlaintextModulus() const;
	NativeInteger GetModulus() const;
	usint GetDimension() const;

	const NativePoly::DugType& GetDiscreteUniformGenerator() const;
	const NativePoly::DggType& GetDiscreteGaussianGenerator() const;
	const NativePoly::TugType& GetTernaryUniformGenerator() const;
	const NativePoly::BugType& GetBinaryUniformGenerator() const;

	void SetDiscreteUniformGenerator(shared_ptr<NativePoly::DugType> dug);
	void SetDiscreteGaussianGenerator(shared_ptr<NativePoly::DggType> dgg);
	void SetTernaryUniformGenerator(shared_ptr<NativePoly::TugType> tug);
	void SetBinaryUniformGenerator(shared_ptr<NativePoly::BugType> bug);

};

class ILWEKey{
private:
	std::shared_ptr<ILWEParams> m_params;

public :
	ILWEKey(const std::shared_ptr<ILWEParams> params);

	const std::shared_ptr<ILWEParams> GetLWEParams() const;
};

class ILWECiphertext: public ILWEKey{
private:
	shared_ptr<ILWE> m_element;
public:
	ILWECiphertext(const shared_ptr<ILWEParams> params);

	ILWECiphertext(const ILWECiphertext &rhs);

	const NativeVector& GetA() const;

	void SetA(const NativeVector& a);

	const NativeInteger& GetB() const;

	void SetB(const NativeInteger &b);

	usint GetSizeInBytes();
};

class ILWESecretKey:public ILWEKey{
private:
	NativeVector m_sk;
public:
	ILWESecretKey(const shared_ptr<ILWEParams> params);
	void SetSKElement(const NativeVector &s);
	const NativeVector& GetSKElement() const;
};

class ILWEPublicKey:public ILWEKey{
private:
	std::shared_ptr<ILWE> m_element;
public:
	ILWEPublicKey(const shared_ptr<ILWEParams> params);
	shared_ptr<ILWE> GetPKElement() const;

	void SetA(const NativeVector &a);
	void SetA(NativeVector &&a);
	void SetB(const NativeInteger &b);
};

class ILWEKeyPair{
public:
	ILWEKeyPair(const shared_ptr<ILWEParams> &params);
	shared_ptr<ILWESecretKey> secretkey;
	shared_ptr<ILWEPublicKey> publickey;

};


}
#endif /* LBCRYPTO_INTEGERLWE_H */
