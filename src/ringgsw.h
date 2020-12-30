#ifndef LBCRYPTO_CRYPTO_RGSW_H
#define LBCRYPTO_CRYPTO_RGSW_H

//Includes Section
#include <palisade.h>
#include "scheme/rlwe.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
//Definations of core classes of RingGSW
namespace lbcrypto {

//forward declarations

template <class Element>
class RGSWKey;

template <class Element>
class LWEForm {

private:
	Element a;
	Element b;

public:

	LWEForm(const Element& a, const Element &b);

	LWEForm(Element &&a, Element &&b);

	LWEForm(const shared_ptr<LPCryptoParameters<Element>> params);

	const Element& GetA() const;

	Element& GetA() ;

	void SetA(const Element& a);

	void SetA(Element &&a);

	const Element& GetB() const;

	Element& GetB() ;

	void SetB(const Element& b);

	void SetB(Element &&b);

	void SwitchFormat();

	void ModReduce(const typename Element::Integer &p);

	void NegateSelf();

	void SetAForTowerIdx(const NativePoly &aPoly, usint t);

	void SetBForTowerIdx(const NativePoly &bPoly, usint t);

	void SetAForTowerIdx(NativePoly &&aPoly, usint t);

	void SetBForTowerIdx(NativePoly &&bPoly, usint t);

};

template <class Element>
class RGSWKey {

private:
	std::shared_ptr<LPCryptoParameters<Element>> cryptoParams;

public:

	RGSWKey(const std::shared_ptr<LPCryptoParameters<Element>> params);

	const std::shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const;
};

//ciphertext of ring gsw form
template <class Element>
class RGSWCiphertext: public RGSWKey<Element> {

private:
	std::vector<LWEForm<Element>> m_element;

public:

	RGSWCiphertext(const shared_ptr<LPCryptoParameters<Element>> params);

	const std::vector<LWEForm<Element>>& GetElements() const;

	std::vector<LWEForm<Element>>& GetElements();

	const LWEForm<Element>& operator[](usint idx) const ;

	LWEForm<Element>& operator[](usint idx) ;

	void SetElementAtIndex(usint idx, const Element &valueB, const Element& valueA);

	void SetElementAtIndex(usint idx, Element &&valueB, Element &&valueA);

	void SwitchFormat();

	void ModReduce();

	void NegateSelf();

	void SetElementAtIndexForTower(usint rowIdx, usint t, const NativePoly &valueB, const NativePoly &valueA);

	void SetElementAtIndexForTower(usint rowIdx, usint t, NativePoly &&valueB, NativePoly &&valueA);

	usint GetSizeInBytes();

	friend inline std::ostream& operator<<(std::ostream& os, const RGSWCiphertext& cipher){
		os << "No of rows in the ciphertext is \t"<< cipher.m_element.size()<<"\n\n";

		for (usint i = 0; i < cipher.m_element.size(); i++) {
			os << "Print component A at row idx "<< i << "\n\n" << cipher.m_element[i].GetA() << "\n\n";
			os << "Print component B at row idx "<< i << "\n\n" << cipher.m_element[i].GetB() << "\n\n";
		}
		return os;
	}
};

template <class Element>
class RGSWPublicKey: public RGSWKey<Element> {

private:
	shared_ptr<LWEForm<Element>> m_elements;

public:
	RGSWPublicKey(const shared_ptr<LPCryptoParameters<Element>> params);

	const LWEForm<Element>& GetPublicElements() const;

	void SetPublicElements(const Element &a,const Element &b);

	void SetPublicElements(Element &&a, Element &&b);

};

template <class Element>
class RGSWSecretKey: public RGSWKey<Element> {
private:
	std::shared_ptr<Element> m_sk;

public:
	RGSWSecretKey(const shared_ptr<LPCryptoParameters<Element>> params);

	const Element& GetSecretKey();
	void SetSecretKey(const Element& value);
	void SetSecretKey(Element &&value);
};

template <class Element>
class RGSWKeySwitchMatrix: public RGSWKey<Element> {
private:
	std::vector<RGSWCiphertext<Element>> m_key;

public:
	RGSWKeySwitchMatrix(const shared_ptr<LPCryptoParameters<Element>> params);

	const RGSWCiphertext<Element>& GetKeyMatrixAtIndex(usint idx);

	void SetKeyMatrixAtIndex(usint idx, const RGSWCiphertext<Element> &key);

	void SetKeyMatrixAtIndex(usint idx, RGSWCiphertext<Element> &&key);
};

template <class Element>
class RGSWKeyPair {
public:
	std::shared_ptr<RGSWSecretKey<Element>> secretKey;
	std::shared_ptr<RGSWPublicKey<Element>> publicKey;

	RGSWKeyPair(const shared_ptr<LPCryptoParameters<Element>> params);
};

}
#endif
