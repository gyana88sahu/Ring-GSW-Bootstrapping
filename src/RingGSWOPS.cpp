#ifndef LBCRYPTO_CRYPTO_RGSWOPS_C
#define LBCRYPTO_CRYPTO_RGSWOPS_C

#include "RingGSWOPS.h"
#include "ringgsw.cpp"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <class Element>
using GridCipherTypeBV = std::vector<std::shared_ptr<LWEForm<Element>>>;

template <class Element>
shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::oneCipher = nullptr;

template <class Element>
std::vector<std::shared_ptr<RGSWCiphertext<Element>>> RGSWOps<Element>::circularKey = std::vector<std::shared_ptr<RGSWCiphertext<Element>>>();

template <class Element>
shared_ptr<Element> RGSWOps<Element>::oneMinusX = nullptr;

template <class Element>
shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::onePlusX = nullptr;

template <class Element>
std::vector<std::shared_ptr<RGSWKeySwitchMatrix<Element>>> RGSWOps<Element>::maskKeysGSW = std::vector<std::shared_ptr<RGSWKeySwitchMatrix<Element>>>();

template <class Element>
std::vector<std::shared_ptr<RGSWCiphertext<Element>>> RGSWOps<Element>::maskKeysBV = std::vector<std::shared_ptr<RGSWCiphertext<Element>>>();

template <class Element>
shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::logNInverseCipher = nullptr;

template <class Element>
std::vector<shared_ptr<RGSWCiphertext<Element>>> RGSWOps<Element>::rgswPowerCache = std::vector<shared_ptr<RGSWCiphertext<Element>>>();


template <class Element>
RGSWOps<Element>::RGSWOps(){

}

template <class Element>
RGSWKeyPair<Element> RGSWOps<Element>::KeyGen(const shared_ptr<LPCryptoParameters<Element>> cryptoParams) {

	const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);

	RGSWKeyPair<Element> kp(cryptoParams);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	typename Element::DugType dug;
	typename Element::TugType tug;

	//Generate the secret key
	Element s(tug, elementParams, Format::COEFFICIENT);

	s.SwitchFormat();

	//Generate the uniformly random element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	Element e(dgg, elementParams, Format::EVALUATION);

	Element b = a*s + p*e;

	kp.publicKey->SetPublicElements(std::move(a),std::move(b));

	kp.secretKey->SetSecretKey(std::move(s));

	return kp;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Encrypt(const RGSWPublicKey<Element> &pk, Element &m) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<Element>> ciphertext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const typename Element::TugType tug;

	//const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	const Element &a = pk.GetPublicElements().GetA();
	const Element &b = pk.GetPublicElements().GetB();

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1 + m * (powersOfBaseInit << (base * i)));

		Element aPoly(a * r + p * e0);

		//Element bPoly(b * r  + m * (powersOfBaseInit << (base * i)));

		//Element aPoly(a * r );


		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1);

		Element aPoly(a * r + p * e0 + m * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return ciphertext;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Encrypt(const RGSWPublicKey<Element> &pk, uint64_t m){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<Element>> ciphertext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const typename Element::TugType tug;

	//const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	Element mssg(elementParams, COEFFICIENT, true);
	mssg[0] = typename Element::Integer(m);

	mssg.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	const Element &a = pk.GetPublicElements().GetA();
	const Element &b = pk.GetPublicElements().GetB();

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1 + mssg * (powersOfBaseInit << (base * i)));

		Element aPoly(a * r + p * e0);

		//Element bPoly(b * r  + m * (powersOfBaseInit << (base * i)));

		//Element aPoly(a * r );


		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1);

		Element aPoly(a * r + p * e0 + mssg * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return ciphertext;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::BootEncrypt(const RGSWPublicKey<Element> &pk, Element &m){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	auto ciphertext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	auto p = cryptoParamsBGV->GetPlaintextModulus();
	//p = p*2;

	const typename Element::TugType tug;

	//const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	auto a( pk.GetPublicElements().GetA());
	auto b( pk.GetPublicElements().GetB());


	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1 + m * (powersOfBaseInit << (base * i)));

		Element aPoly(a * r + p * e0);

		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1);

		Element aPoly(a * r + p * e0 + m * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return ciphertext;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ClearEncrypt(const RGSWPublicKey<Element> &pk, Element &m){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<Element>> cleartext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	for (usint i = 0; i < l; i++) {

		Element bPoly(m * (powersOfBaseInit << (base * i)));

		Element aPoly(elementParams, EVALUATION, true);

		cleartext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element bPoly(elementParams, EVALUATION, true);

		Element aPoly(m * (powersOfBaseInit << (base * i)));

		cleartext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return cleartext;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, Element &m){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);

	auto cleartext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	for (usint i = 0; i < l; i++) {

		Element bPoly(m * (powersOfBaseInit << (base * i)));

		Element aPoly(elementParams, EVALUATION, true);

		cleartext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element bPoly(elementParams, EVALUATION, true);

		Element aPoly(m * (powersOfBaseInit << (base * i)));

		cleartext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return cleartext;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, uint64_t m){
	Element messg(cryptoParams->GetElementParams(), COEFFICIENT, true);
	messg[0] = typename Element::Integer(m);
	auto result = RGSWOps<Element>::ClearEncrypt(cryptoParams, messg);
	return result;
}

template <class Element>
Element RGSWOps<Element>::Decrypt(const std::shared_ptr<RGSWCiphertext<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk) {
	Element result;

	const auto cryptoParams = sk->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();
	const auto &c = ciphertext->GetElements();
	const auto &s = sk->GetSecretKey();

	Element b = c[0].GetB() - s * c[0].GetA();

	b.SwitchFormat();

	//cout << "printing noise b\n" << b << "\n\n";

	result = b.Mod(p);

	return result;
}

template <class Element>
Element RGSWOps<Element>::Decrypt(const std::shared_ptr<LWEForm<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk){
	Element result;

	const auto cryptoParams = sk->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();
	const auto &s = sk->GetSecretKey();

	/*cout << "printing A vector " << ciphertext->GetA() << '\n';
	cout << "printing B vector " << ciphertext->GetB() << '\n';*/


	Element b = ciphertext->GetB() - s * ciphertext->GetA();

	b.SwitchFormat();

	//cout << "printing noise vector " << b << '\n';

	result = b.Mod(p);

	return result;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Add(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<RGSWCiphertext<Element>> b) {
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());
	auto result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint N = a->GetElements().size(); //N = 2l

	for (usint i = 0; i < N; i++) {
		Element aPoly( (*a)[i].GetA() + (*b)[i].GetA());
		Element bPoly( (*a)[i].GetB() + (*b)[i].GetB());
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	return result;
}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::Add(const std::shared_ptr<LWEForm<Element>> a,const std::shared_ptr<LWEForm<Element>> b){
	auto bResultPoly = std::move(a->GetB() + b->GetB());
	auto aResultPoly = std::move(a->GetA() + b->GetA());

	auto result = make_shared<LWEForm<Element>>(std::move(aResultPoly), std::move(bResultPoly));

	return result;
}


template <class Element>
void RGSWOps<Element>::AddInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());

	usint N = a->GetElements().size(); //N = 2l

	for (usint i = 0; i < N; i++) {
		(*b)[i].GetA() += (*a)[i].GetA();
		(*b)[i].GetB() += (*a)[i].GetB();
	}
}

template <class Element>
void RGSWOps<Element>::AddInPlaceBV(const std::vector<shared_ptr<LWEForm<Element>>> a, std::vector<shared_ptr<LWEForm<Element>>> b){
	for(usint i=0; i< 2; i++){
		b[i]->GetB() += a[i]->GetB();
		b[i]->GetA() += a[i]->GetA();
	}
}

template <class Element>
void RGSWOps<Element>::AddOneInPlace(std::shared_ptr<RGSWCiphertext<Element>> a){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());
	usint N = a->GetElements().size(); //N = 2l
	usint l = N >> 1;

	auto &aRef = *a;

	for (usint i = 0; i < l; i++) {
		aRef[i].GetB() += (*oneCipher)[i].GetB();
	}

	for (usint i = l; i < N; i++) {
		aRef[i].GetA() += (*oneCipher)[i].GetA();
	}

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Subtract(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());
	auto result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint N = a->GetElements().size(); //N = 2l

	for (usint i = 0; i < N; i++) {
		Element aPoly( (*a)[i].GetA() - (*b)[i].GetA());
		Element bPoly( (*a)[i].GetB() - (*b)[i].GetB());
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	return result;
}
//b -= a
template <class Element>
void RGSWOps<Element>::SubtractInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a,const std::shared_ptr<RGSWCiphertext<Element>> b){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());

	usint N = a->GetElements().size(); //N = 2l

	for (usint i = 0; i < N; i++) {
		(*b)[i].GetA() -= (*a)[i].GetA();
		(*b)[i].GetB() -= (*a)[i].GetB();
	}
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ClearRingMultiply(const Element &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());
	shared_ptr<RGSWCiphertext<Element>> result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint N = cipher->GetElements().size(); //N = 2l
	for (usint i = 0; i < N; i++) {
		const auto& aPoly = (*cipher)[i].GetA();
		const auto& bPoly = (*cipher)[i].GetB();
		auto aPolyResult(aPoly*a);
		auto bPolyResult(bPoly*a);
		result->SetElementAtIndex(i,std::move(bPolyResult),std::move(aPolyResult));
	}

	return result;
}

template <class Element>
void RGSWOps<Element>::ClearRingMultiplyInPlace(const Element &a, shared_ptr<RGSWCiphertext<Element>> cipher){
	usint rows = cipher->GetElements().size();

	for (usint i = 0; i < rows; i++) {
		(*cipher)[i].GetA() *= a;
		(*cipher)[i].GetB() *= a;
	}
}

template <class Element>
void RGSWOps<Element>::ClearRingMultiplyInPlace(const Element &a, shared_ptr<LWEForm<Element>> cipher){
	cipher->GetA() *= a;
	cipher->GetB() *= a;
}

template <class Element>
void RGSWOps<Element>::ClearRingMultiplyInPlace(const Element &a, GridCipherTypeGSW<Element> &cipher){
	usint gridDim = cipher.size();

	for (usint i = 0; i < gridDim; i++) {
		ClearRingMultiplyInPlace(a, cipher[i]);
	}
}

template <class Element>
void RGSWOps<Element>::ClearRingMultiplyInPlace(const Element &a, GridCipherTypeBV<Element> &cipher){
	usint gridDim = cipher.size();

	for (usint i = 0; i < gridDim; i++) {
		ClearRingMultiplyInPlace(a, cipher[i]);
	}
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<RGSWCiphertext<Element>> b) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());
	shared_ptr<RGSWCiphertext<Element>> result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint N = a->GetElements().size(); //N = 2l
	usint l = N>>1;

	for (usint i = 0; i < N; i++) {
		const auto& aPoly = (*a)[i].GetA();
		const auto& bPoly = (*a)[i].GetB();
		const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
		const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

		auto bResultPoly(bPolyDigits[0] * (*b)[0].GetB());
		auto aResultPoly(bPolyDigits[0] * (*b)[0].GetA());

		for (usint j = 1; j < l; j++) {
			bResultPoly+= bPolyDigits[j] * (*b)[j].GetB();
			aResultPoly+= bPolyDigits[j] * (*b)[j].GetA();
		}
		for (usint j = l; j < N; j++) {
			bResultPoly+= aPolyDigits[j-l] * (*b)[j].GetB();
			aResultPoly+= aPolyDigits[j-l] * (*b)[j].GetA();
		}
		result->SetElementAtIndex(i,std::move(bResultPoly),std::move(aResultPoly));
	}

	return result;
}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<LWEForm<Element>> b){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint N = a->GetElements().size(); //N = 2l
	usint l = N>>1;

	const auto& aPoly = b->GetA();
	const auto& bPoly = b->GetB();
	const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
	const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

	auto bResultPoly(bPolyDigits[0] * (*a)[0].GetB());
	auto aResultPoly(bPolyDigits[0] * (*a)[0].GetA());

	for (usint j = 1; j < l; j++) {
		bResultPoly+= bPolyDigits[j] * (*a)[j].GetB();
		aResultPoly+= bPolyDigits[j] * (*a)[j].GetA();
	}
	for (usint j = l; j < N; j++) {
		bResultPoly+= aPolyDigits[j-l] * (*a)[j].GetB();
		aResultPoly+= aPolyDigits[j-l] * (*a)[j].GetA();
	}

	auto result = std::make_shared<LWEForm<Element>>(std::move(aResultPoly), std::move(bResultPoly));

	return std::move(result);
}

template <class Element>
void RGSWOps<Element>::MultiplyInPlace(const std::shared_ptr<RGSWCiphertext<Element>> a, std::shared_ptr<LWEForm<Element>> b){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint N = a->GetElements().size(); //N = 2l
	usint l = N>>1;

	auto& aPoly = b->GetA();
	auto& bPoly = b->GetB();
	const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
	const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

	bPoly = (bPolyDigits[0] * (*a)[0].GetB());
	aPoly = (bPolyDigits[0] * (*a)[0].GetA());

	for (usint j = 1; j < l; j++) {
		bPoly+= bPolyDigits[j] * (*a)[j].GetB();
		aPoly+= bPolyDigits[j] * (*a)[j].GetA();
	}
	for (usint j = l; j < N; j++) {
		bPoly+= aPolyDigits[j-l] * (*a)[j].GetB();
		aPoly+= aPolyDigits[j-l] * (*a)[j].GetA();
	}

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ScalarMultiply(const typename Element::Integer &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());
	auto result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);
	auto &modulus = cryptoParamsBGV->GetElementParams()->GetModulus();
	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint base = 1 << relinWindow;
	usint N = cipher->GetElements().size(); //N = 2l
	usint l = N >> 1;

	typename Element::Integer powersOfBaseInit(1);//2^r

	for (usint i = 0; i < l; i++) {

		typename Element::Integer aPower = a.ModMul((powersOfBaseInit << (relinWindow * i)), modulus);
		typename Element::Integer aPowerTau(aPower.GetDigitAtIndexForBase(1, base));
		auto bPoly((*cipher)[0].GetB()*aPowerTau);
		auto aPoly((*cipher)[0].GetA()*aPowerTau);
		for(usint j=1; j<l;j++){
			aPowerTau = typename Element::Integer(aPower.GetDigitAtIndexForBase(j+1, base));
			bPoly += (*cipher)[j].GetB()*aPowerTau;
			aPoly += (*cipher)[j].GetA()*aPowerTau;
		}
		result->SetElementAtIndex(i,std::move(bPoly),std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = l; i < N; i++) {
		typename Element::Integer aPower = a.ModMul((powersOfBaseInit << (relinWindow * (i-l))), modulus);
		typename Element::Integer aPowerTau(aPower.GetDigitAtIndexForBase(1, base));
		auto bPoly((*cipher)[l].GetB()*aPowerTau);
		auto aPoly((*cipher)[l].GetA()*aPowerTau);
		for(usint j=1; j<l;j++){
			aPowerTau = typename Element::Integer(aPower.GetDigitAtIndexForBase(j+1, base));
			bPoly += (*cipher)[j+l].GetB()*aPowerTau;
			aPoly += (*cipher)[j+l].GetA()*aPowerTau;
		}
		result->SetElementAtIndex(i,std::move(bPoly),std::move(aPoly));
	}

	return result;
}

template <class Element>
std::vector<shared_ptr<LWEForm<Element>>> RGSWOps<Element>::ScalarMultiplyBV(const typename Element::Integer &a, const std::shared_ptr<RGSWCiphertext<Element>> cipher){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());
	std::vector<shared_ptr<LWEForm<Element>>> result;

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint base = 1 << relinWindow;
	usint N = cipher->GetElements().size(); //N = 2l
	usint l = N >> 1;

	typename Element::Integer aTau(a.GetDigitAtIndexForBase(1, base));
	auto bPoly0((*cipher)[0].GetB() * aTau);
	auto aPoly0((*cipher)[0].GetA() * aTau);
	auto bPoly1((*cipher)[l].GetB() * aTau);
	auto aPoly1((*cipher)[l].GetA() * aTau);
	for (usint j = 1; j < l; j++) {
		aTau = typename Element::Integer(a.GetDigitAtIndexForBase(j + 1, base));
		bPoly0 += (*cipher)[j].GetB() * aTau;
		aPoly0 += (*cipher)[j].GetA() * aTau;
		bPoly1 += (*cipher)[j + l].GetB() * aTau;
		aPoly1 += (*cipher)[j + l].GetA() * aTau;
	}

	auto row0 = std::make_shared<LWEForm<Element>>(std::move(aPoly0), std::move(bPoly0));
	auto row1 = std::make_shared<LWEForm<Element>>(std::move(aPoly1), std::move(bPoly1));

	result.push_back(std::move(row0));
	result.push_back(std::move(row1));

	return std::move(result);
}

template <class Element>
std::shared_ptr<RGSWKeySwitchMatrix<Element>> RGSWOps<Element>::KeySwitchGen(const std::shared_ptr<RGSWSecretKey<Element>> oldSk,const std::shared_ptr<RGSWSecretKey<Element>> newSk){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(oldSk->GetCryptoParameters());

	RGSWCiphertext<Element> ek0(cryptoParamsBGV);
	RGSWCiphertext<Element> ek1(cryptoParamsBGV);

	auto result = make_shared<RGSWKeySwitchMatrix<Element>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	const typename Element::TugType tug;

	const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	typename Element::DugType dug;

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	typename Element::Integer powersOfBaseInit(1);//2^r

	Element aPrime(dug, elementParams, EVALUATION);

	Element bPrime = aPrime * newSk->GetSecretKey() ; //b = as

	const Element& skOldElement = oldSk->GetSecretKey();

	Element one(elementParams, COEFFICIENT, true);
	one[0] = 1;
	one.SwitchFormat();

	//one should be deleted as it has no role

	for (usint i = 0; i < l; i++) {
		Element r(tug, elementParams, EVALUATION);
		//Element e0(dgg, elementParams, EVALUATION);
		Element e1(dgg, elementParams, EVALUATION);

		//Element a = aPrime * r + p*e0;
		Element a = aPrime * r;
		Element b = bPrime * r + one * (powersOfBaseInit << (base * i)) + p*e1;
		ek0.SetElementAtIndex(i, std::move(b), std::move(a));
	}

	for (usint i = 0; i < l; i++) {
		Element r(tug, elementParams, EVALUATION);
		//Element e0(dgg, elementParams, EVALUATION);
		Element e1(dgg, elementParams, EVALUATION);

		//Element a = aPrime * r + p*e0;
		Element a = aPrime * r;
		Element b = bPrime * r - skOldElement * (powersOfBaseInit << (base * i));
		ek0.SetElementAtIndex(i + l, std::move(b), std::move(a));
	}

	for (usint i = 0; i < l; i++) {
		Element r(tug, elementParams, EVALUATION);
		//Element e0(dgg, elementParams, EVALUATION);
		Element e1(dgg, elementParams, EVALUATION);

		//Element a = aPrime * r + one * (powersOfBaseInit << (base * i)) + p*e0;
		Element a = aPrime * r + one * (powersOfBaseInit << (base * i));
		Element b = bPrime * r + p*e1;
		ek1.SetElementAtIndex(i, std::move(b), std::move(a));
	}

	for (usint i = 0; i < l; i++) {
		Element r(tug, elementParams, EVALUATION);
		//Element e0(dgg, elementParams, EVALUATION);
		Element e1(dgg, elementParams, EVALUATION);

		//Element a = aPrime * r - skOldElement *(powersOfBaseInit << (base * i)) + p*e0;
		Element a = aPrime * r - skOldElement *(powersOfBaseInit << (base * i));
		Element b = bPrime * r + p*e1;
		ek1.SetElementAtIndex(i+l, std::move(b), std::move(a));
	}

	result->SetKeyMatrixAtIndex(0, std::move(ek0));
	result->SetKeyMatrixAtIndex(1, std::move(ek1));

	return result;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::KeySwitchGenBV(const std::shared_ptr<RGSWSecretKey<Element>> oldSk,const std::shared_ptr<RGSWSecretKey<Element>> newSk){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(oldSk->GetCryptoParameters());

	auto ek = make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	const typename Element::TugType tug;

	const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	typename Element::DugType dug;

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	typename Element::Integer powersOfBaseInit(1);//2^r

	Element aPrime(dug, elementParams, EVALUATION);

	Element bPrime = aPrime * newSk->GetSecretKey() ; //b = as

	const Element& skOldElement = oldSk->GetSecretKey();

	for (usint i = 0; i < l; i++) {
		Element r(tug, elementParams, EVALUATION);
		Element e0(dgg, elementParams, EVALUATION);
		Element e1(dgg, elementParams, EVALUATION);

		Element a(aPrime * r + p*e0);
		Element b(bPrime * r - skOldElement * (powersOfBaseInit << (base * i)) + p*e1 );
		ek->SetElementAtIndex(i, std::move(b), std::move(a));
	}

	return ek;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::KeySwitch(const std::shared_ptr<RGSWCiphertext<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipherOld->GetCryptoParameters());
	auto result = make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint N = cipherOld->GetElements().size();
	usint l = N >> 1;
	usint relinWindow = cipherOld->GetCryptoParameters()->GetRelinWindow();

	std::vector<std::vector<Element>> cipherOldBD_AComponent;
	std::vector<std::vector<Element>> cipherOldBD_BComponent;
	for (usint i = 0; i < l; i++){
		const auto& aPoly = (*cipherOld)[i].GetA();
		const auto& bPoly = (*cipherOld)[i].GetB();
		cipherOldBD_AComponent.push_back(std::move(aPoly.BaseDecompose(relinWindow)));
		cipherOldBD_BComponent.push_back(std::move(bPoly.BaseDecompose(relinWindow)));
	}

	for (usint i = 0; i < l; i++) {

		const auto& aPolyDigits = cipherOldBD_AComponent[i];
		const auto& bPolyDigits = cipherOldBD_BComponent[i];

		auto bResultPoly(bPolyDigits[0] * evalKey->GetKeyMatrixAtIndex(0)[0].GetB());
		auto aResultPoly(bPolyDigits[0] * evalKey->GetKeyMatrixAtIndex(0)[0].GetA());

		for (usint j = 1; j < l; j++) {
			bResultPoly+= bPolyDigits[j] * evalKey->GetKeyMatrixAtIndex(0)[j].GetB();
			aResultPoly+= bPolyDigits[j] * evalKey->GetKeyMatrixAtIndex(0)[j].GetA();
		}

		for (usint j = l; j < N; j++) {
			bResultPoly+= aPolyDigits[j-l] * evalKey->GetKeyMatrixAtIndex(0).GetElements().at(j).GetB();
			aResultPoly+= aPolyDigits[j-l] * evalKey->GetKeyMatrixAtIndex(0).GetElements().at(j).GetA();
		}

		result->SetElementAtIndex(i,std::move(bResultPoly),std::move(aResultPoly));
	}

	for (usint i = 0; i < l; i++) {

		const auto& aPolyDigits = cipherOldBD_AComponent[i];
		const auto& bPolyDigits = cipherOldBD_BComponent[i];

		auto bResultPoly(bPolyDigits[0] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(0).GetB());
		auto aResultPoly(bPolyDigits[0] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(0).GetA());

		for (usint j = 1; j < l; j++) {
			bResultPoly+= bPolyDigits[j] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(j).GetB();
			aResultPoly+= bPolyDigits[j] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(j).GetA();
		}

		for (usint j = l; j < N; j++) {
			bResultPoly+= aPolyDigits[j-l] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(j).GetB();
			aResultPoly+= aPolyDigits[j-l] * evalKey->GetKeyMatrixAtIndex(1).GetElements().at(j).GetA();
		}

		result->SetElementAtIndex(i+l,std::move(bResultPoly),std::move(aResultPoly));
	}

	return result;

}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::KeySwitchUpper(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey){
	auto &keySwitchMatrix = evalKey->GetKeyMatrixAtIndex(0);
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(keySwitchMatrix.GetCryptoParameters());

	usint rows = keySwitchMatrix.GetElements().size();
	usint l = rows >> 1;
	usint relinWindow = keySwitchMatrix.GetCryptoParameters()->GetRelinWindow();
	auto aPolyDigits = std::move(cipherOld->GetA().BaseDecompose(relinWindow));
	auto bPolyDigits = std::move(cipherOld->GetB().BaseDecompose(relinWindow));

	auto bPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix[0].GetB()));
	auto aPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix[0].GetA()));

	for(usint i=1; i<l;i++){
		bPolyResult += bPolyDigits[i]*keySwitchMatrix[i].GetB();
		aPolyResult += bPolyDigits[i]*keySwitchMatrix[i].GetA();
	}

	for(usint i=0; i<l;i++){
		bPolyResult += aPolyDigits[i]*keySwitchMatrix[i+l].GetB();
		aPolyResult += aPolyDigits[i]*keySwitchMatrix[i+l].GetA();
	}

	auto result = make_shared<LWEForm<Element>>(std::move(aPolyResult), std::move(bPolyResult));

	return result;
}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::KeySwitchLower(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey){
	auto &keySwitchMatrix = evalKey->GetKeyMatrixAtIndex(1);
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(keySwitchMatrix.GetCryptoParameters());

	usint rows = keySwitchMatrix.GetElements().size();
	usint l = rows >> 1;
	usint relinWindow = keySwitchMatrix.GetCryptoParameters()->GetRelinWindow();
	auto aPolyDigits = std::move(cipherOld->GetA().BaseDecompose(relinWindow));
	auto bPolyDigits = std::move(cipherOld->GetB().BaseDecompose(relinWindow));

	auto bPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix[0].GetB()));
	auto aPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix[0].GetA()));

	for(usint i=1; i<l;i++){
		bPolyResult += bPolyDigits[i]*keySwitchMatrix[i].GetB();
		aPolyResult += bPolyDigits[i]*keySwitchMatrix[i].GetA();
	}

	for(usint i=0; i<l;i++){
		bPolyResult += aPolyDigits[i]*keySwitchMatrix[i+l].GetB();
		aPolyResult += aPolyDigits[i]*keySwitchMatrix[i+l].GetA();
	}

	auto result = make_shared<LWEForm<Element>>(std::move(aPolyResult), std::move(bPolyResult));

	return result;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::KeySwitchLeanRGSW(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWKeySwitchMatrix<Element>> evalKey){
	auto &keySwitchMatrix0 = evalKey->GetKeyMatrixAtIndex(0);
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(keySwitchMatrix0.GetCryptoParameters());

	auto result = make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);


	usint rows = keySwitchMatrix0.GetElements().size();
	usint l = rows >> 1;
	usint relinWindow = keySwitchMatrix0.GetCryptoParameters()->GetRelinWindow();
	auto aPolyDigits = std::move(cipherOld->GetA().BaseDecompose(relinWindow));
	auto bPolyDigits = std::move(cipherOld->GetB().BaseDecompose(relinWindow));

	{
		auto bPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix0[0].GetB()));
		auto aPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix0[0].GetA()));

		for(usint i=1; i<l;i++){
			bPolyResult += bPolyDigits[i]*keySwitchMatrix0[i].GetB();
			aPolyResult += bPolyDigits[i]*keySwitchMatrix0[i].GetA();
		}

		for(usint i=0; i<l;i++){
			bPolyResult += aPolyDigits[i]*keySwitchMatrix0[i+l].GetB();
			aPolyResult += aPolyDigits[i]*keySwitchMatrix0[i+l].GetA();
		}

		result->SetElementAtIndex(0,std::move(bPolyResult),std::move(aPolyResult));

	}

	auto &keySwitchMatrix1 = evalKey->GetKeyMatrixAtIndex(1);

	{
		auto bPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix1[0].GetB()));
		auto aPolyResult(std::move(bPolyDigits[0]*keySwitchMatrix1[0].GetA()));

		for(usint i=1; i<l;i++){
			bPolyResult += bPolyDigits[i]*keySwitchMatrix1[i].GetB();
			aPolyResult += bPolyDigits[i]*keySwitchMatrix1[i].GetA();
		}

		for(usint i=0; i<l;i++){
			bPolyResult += aPolyDigits[i]*keySwitchMatrix1[i+l].GetB();
			aPolyResult += aPolyDigits[i]*keySwitchMatrix1[i+l].GetA();
		}

		result->SetElementAtIndex(1,std::move(bPolyResult),std::move(aPolyResult));

	}

	return result;
}


template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::KeySwitchBV(const std::shared_ptr<LWEForm<Element>> cipherOld, const std::shared_ptr<RGSWCiphertext<Element>> evalKey){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(evalKey->GetCryptoParameters());

	usint l = evalKey->GetElements().size();
	usint relinWindow = evalKey->GetCryptoParameters()->GetRelinWindow();
	auto aPolyDigits = std::move(cipherOld->GetA().BaseDecompose(relinWindow));

	auto bResultPoly(aPolyDigits[0]*(*evalKey)[0].GetB());
	auto aResultPoly(aPolyDigits[0]*(*evalKey)[0].GetA());

	for(usint i=1; i<l;i++){
		bResultPoly += aPolyDigits[i]*(*evalKey)[i].GetB();
		aResultPoly += aPolyDigits[i]*(*evalKey)[i].GetA();
	}

	bResultPoly += cipherOld->GetB();

	auto result = make_shared<LWEForm<Element>>(std::move(aResultPoly), std::move(bResultPoly));

	return result;

}

template <class Element>
void RGSWOps<Element>::ModReduce(const std::shared_ptr<LWEForm<Element>> cipher, const typename Element::Integer &q, const shared_ptr<LPCryptoParameters<Element>> cryptoParams){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);
	auto &modulus = cryptoParams->GetElementParams()->GetModulus();
	auto N = cryptoParams->GetElementParams()->GetRingDimension();
	const auto p = cryptoParamsBGV->GetPlaintextModulus();
	//usint qInt = q.ConvertToInt();
	//double qDouble = qInt;
	//usint QInt = modulus.ConvertToInt();
	//double QDouble = modulus;

	auto &aComp = cipher->GetA();
	auto &bComp = cipher->GetB();
	aComp.SwitchFormat();
	bComp.SwitchFormat();

	for(usint i= 0; i < N; i++){
		auto num = aComp[i];
		num = num*q;
		num = num/modulus;

		auto diff = (aComp[i].Mod(p)).ModSub(num.Mod(p),p);
		aComp[i] = num + diff;
	}

	auto num = bComp[0];
	num = num*q;
	num = num/modulus;

	auto diff = (bComp[0].Mod(p)).ModSub(num.Mod(p),p);
	bComp[0] = num + diff;

}

template <class Element>
void RGSWOps<Element>::SetOneCipher(const shared_ptr<LPCryptoParameters<Element>> cryptoParams){

	const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);

	shared_ptr<RGSWCiphertext<Element>> ciphertext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	Element one(elementParams, COEFFICIENT, true);
	one[0] = typename Element::Integer(1);
	one.SwitchFormat();

	Element zeroPoly(elementParams, EVALUATION, true);

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	for (usint i = 0; i < l; i++) {

		Element bPoly(one * (powersOfBaseInit << (base * i)));

		Element aPoly(zeroPoly);

		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element bPoly(zeroPoly);

		Element aPoly(one * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	oneCipher = ciphertext;

}

template <class Element>
void RGSWOps<Element>::InitializeCircularKey(const RGSWKeyPair<Element> &kp){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(kp.publicKey->GetCryptoParameters());
	const auto elementParams = cryptoParamsBGV->GetElementParams();
	//RGSWPublicKey<Element> newPK(cryptoParamsBGV);
	/*const auto &aPub = kp.publicKey->GetPublicElements().GetA();
	const auto &bPub = kp.publicKey->GetPublicElements().GetB();*/
	const auto &s = kp.secretKey->GetSecretKey();
	/*auto noise(bPub - aPub*s);
	noise *= typename Element::Integer(2); //even noise*/
	/*auto aPubNew(aPub);
	auto bPubNew(aPub*s + noise);
	newPK.SetPublicElements(std::move(aPubNew),std::move(bPubNew));*/

	auto skEl(s);
	skEl.SwitchFormat();
	cout << "printing secret keys \n " << skEl << "\n\n";

	usint N = elementParams->GetRingDimension();

	std::shared_ptr<RGSWCiphertext<Element>> skCipher = nullptr;

	for(usint i=0; i<N;i++){

		Element enc(elementParams, COEFFICIENT, true);
		enc[0] = skEl[i];
		skCipher = RGSWOps<Element>::BootEncrypt(*kp.publicKey, enc);
		circularKey.push_back(skCipher);
	}

}

template <class Element>
void RGSWOps<Element>::InitializeMaskKey(const RGSWKeyPair<Element> &kp){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(kp.publicKey->GetCryptoParameters());
	const auto elementParams = cryptoParamsBGV->GetElementParams();
	usint N = elementParams->GetRingDimension();

	usint NBits = log2(N);

	for (usint i = 0; i < NBits; i++) {
		usint idx = 1 << i;
		idx = N / idx + 1;
		auto skMorphed = GetMorphedSecretkey(kp.secretKey, idx);
		auto ksm = RGSWOps<Element>::KeySwitchGen(skMorphed, kp.secretKey);
		maskKeysGSW.push_back(ksm);
	}
}

template <class Element>
void RGSWOps<Element>::InitializeMaskKeyBV(const RGSWKeyPair<Element> &kp){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(kp.publicKey->GetCryptoParameters());
	const auto elementParams = cryptoParamsBGV->GetElementParams();
	usint N = elementParams->GetRingDimension();

	usint NBits = log2(N);

	for (usint i = 0; i < NBits; i++) {
		usint idx = 1 << i;
		idx = N / idx + 1;
		auto skMorphed = GetMorphedSecretkey(kp.secretKey, idx);
		auto ksm = RGSWOps<Element>::KeySwitchGenBV(skMorphed, kp.secretKey);
		maskKeysBV.push_back(ksm);
	}
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ExtractMaskedCipher(std::shared_ptr<LWEForm<Element>> cipher){

	auto cipherAPoly(cipher->GetA());
	auto cipherBPoly(cipher->GetB());
	cipherAPoly.SwitchFormat();
	cipherBPoly.SwitchFormat();

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(circularKey[0]->GetCryptoParameters());

	const auto elementParams = cryptoParamsBGV->GetElementParams();
	const auto &modulus = elementParams->GetModulus();
	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint l = elementParams->GetModulus().GetMSB();
	l = std::ceil((double) l / (double) relinWindow);
	usint base = (1 << relinWindow);

	usint N = elementParams->GetRingDimension();

	Element enc(elementParams, COEFFICIENT, true);
	Element zeroElement(elementParams, EVALUATION, true);
	enc[0] = cipherBPoly[0];
	enc.SwitchFormat();

	std::vector<shared_ptr<LWEForm<Element>>> result;
	auto encCipher0 = make_shared<LWEForm<Element>>(zeroElement, enc);
	auto encCipher1 = make_shared<LWEForm<Element>>(enc, zeroElement); // a, b format

	result.push_back(std::move(encCipher0));
	result.push_back(std::move(encCipher1));

	auto a0(cipherAPoly[0]);
	auto minus_a0 = modulus.ModSub(a0,modulus);
	auto a0s0Cipher = RGSWOps<Element>::ScalarMultiplyBV(minus_a0, circularKey[0]);
	RGSWOps<Element>::AddInPlaceBV(a0s0Cipher, result);

	for (usint i = 1; i < N; i++) {
		auto &ai = cipherAPoly[i];
		auto aisiCipher = RGSWOps<Element>::ScalarMultiplyBV(ai, circularKey[N-i]);
		RGSWOps<Element>::AddInPlaceBV(aisiCipher, result);
	}

	//this loop is for creating a Ring-GSW ciphertext

	std::vector<typename Element::Integer> powers; //powers can be precomputed -> To-DO
	usint powerSize = 2 * l - 1;
	typename Element::Integer mult(base);
	powers.push_back(typename Element::Integer(1));
	for (usint i = 1; i < powerSize; i++) {
		powers.push_back(powers[i-1].ModMul(mult, modulus));
	}

	auto resultGSW = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);
	for (usint i = 0; i < 2; i++) {
		auto &bvPolyB = result[i]->GetB();
		auto &bvPolyA = result[i]->GetA();
		const auto& aPolyDigits = bvPolyA.BaseDecompose(relinWindow);
		const auto& bPolyDigits = bvPolyB.BaseDecompose(relinWindow);

		for (usint row = 0; row < l; row++) {

			usint rowIdx = row + i * l;

			auto bPolyFinal(bPolyDigits[0] * powers[row]);
			auto aPolyFinal(aPolyDigits[0] * powers[row]);
			for (usint k = 1; k < l; k++) {
				bPolyFinal += bPolyDigits[k] * powers[row + k];
				aPolyFinal += aPolyDigits[k] * powers[row + k];
			}

			resultGSW->SetElementAtIndex(rowIdx,std::move(bPolyFinal),std::move(aPolyFinal));

		}
	}


	/*typename Element::Integer twoInverse(2);
	twoInverse = twoInverse.ModInverse(modulus);

	usint matRow = result->GetElements().size();
	for (usint i = 0; i < matRow; i++) {
		(*result)[i].GetA() *= twoInverse;
		(*result)[i].GetB() *= twoInverse;
	}*/

	return std::move(resultGSW);
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ExtractMaskedCipherAlt(std::shared_ptr<LWEForm<Element>> cipher){
	auto cipherAPoly(cipher->GetA());
	auto cipherBPoly(cipher->GetB());
	cipherAPoly.SwitchFormat();
	cipherBPoly.SwitchFormat();

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(circularKey[0]->GetCryptoParameters());

	const auto elementParams = cryptoParamsBGV->GetElementParams();
	const auto &modulus = elementParams->GetModulus();

	usint N = elementParams->GetRingDimension();

	//get encryption of b
	auto result = RGSWOps<Element>::ClearEncrypt(cryptoParamsBGV, cipherBPoly[0].ConvertToInt());
	//multiply and add a0s0
	auto minus_a0 = modulus.ModSub(cipherAPoly[0].ConvertToInt(),modulus);
	auto a0Cipher =  RGSWOps<Element>::ClearEncrypt(cryptoParamsBGV, minus_a0.ConvertToInt());
	auto a0s0Cipher = RGSWOps<Element>::Multiply(a0Cipher, circularKey[0] );
	RGSWOps<Element>::AddInPlace(a0s0Cipher, result);

	for (usint i = 1; i < N; i++) {
		auto &ai = cipherAPoly[i];
		auto aiCipher =  RGSWOps<Element>::ClearEncrypt(cryptoParamsBGV, ai.ConvertToInt());
		auto aisiCipher = RGSWOps<Element>::Multiply(aiCipher, circularKey[N-i]);
		RGSWOps<Element>::AddInPlace(aisiCipher, result);
	}

	return result;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ExtractMaskedCipherAltAlt(std::shared_ptr<RGSWCiphertext<Element>> cipher){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	usint N = elementParams->GetRingDimension();
	usint NBits = maskKeysGSW.size();

	auto cipherAdd = cipher;
	for (usint i = 0; i < NBits; i++) {
		usint idx = 1 << i;
		usint aIdx = N / idx + 1;
		auto cipherMorphed = Automorph(cipherAdd, aIdx);
		cipherMorphed = RGSWOps<Element>::KeySwitch(cipherMorphed, maskKeysGSW[i]);
		//cipherMorphed = RGSWOps<Element>::KeySwitchBV(cipherMorphed, maskKeysBV[i]);
		cipherAdd = RGSWOps<Element>::Add(cipherMorphed, cipherAdd);
	}

	//cipherAdd = RGSWOps<Element>::Multiply(logNInverseCipher, cipherAdd);

	return cipherAdd;
}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::ExtractMaskedCipherAltAlt(std::shared_ptr<LWEForm<Element>> cipher){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(maskKeysBV[0]->GetCryptoParameters());

	const auto elementParams = cryptoParamsBGV->GetElementParams();
	const auto &qRGSW = elementParams->GetModulus();

	usint N = elementParams->GetRingDimension();
	usint NBits = maskKeysBV.size();
	auto NBitsInverse = typename Element::Integer(NBits);
	NBitsInverse = NBitsInverse.ModInverse(qRGSW);


	auto cipherAdd = cipher;
	for (usint i = 0; i < NBits; i++) {
		usint idx = 1<<i;
		usint aIdx = N/idx + 1;
		auto cipherMorphed = Automorph(cipherAdd, aIdx);
		cipherMorphed = RGSWOps<Element>::KeySwitchBV(cipherMorphed, maskKeysBV[i]);
		cipherAdd = RGSWOps<Element>::Add(cipherMorphed, cipherAdd);
	}



	return cipherAdd;
}

template <class Element>
std::shared_ptr<RGSWKeySwitchMatrix<Element>> RGSWOps<Element>::BootStrapKeySwitchGen(const std::shared_ptr<RGSWSecretKey<Element>> sk, const NativeVector &lweSK){
	//sk is the RGSW type secret key used in bootstrapping
	//lweSK is the final secret for the GSW ciphertext
	//this code takes into account a ternary distribution
	//in lwe secret key.

	const auto cryptoParams = sk->GetCryptoParameters();
	auto elementParams = cryptoParams->GetElementParams();
	usint N = elementParams->GetRingDimension();
	const auto &modulus = elementParams->GetModulus();

	auto rgswSK = std::make_shared<RGSWSecretKey<Element>>(cryptoParams);
	Element newRGSWsk(elementParams, COEFFICIENT, true);

	usint dim = lweSK.GetLength(); // lwe/gsw length

	newRGSWsk[0] = (lweSK[0] == NativeInteger(0) || lweSK[0] == NativeInteger(1)) ?
			typename Element::Integer(lweSK[0].ConvertToInt()) : modulus - typename Element::Integer(1);
	for(usint i=1; i < dim ; i++){
		if(lweSK[i] == NativeInteger(0)){
			newRGSWsk[N-i] = 0;
		}
		else if(lweSK[i] == NativeInteger(1)){
			newRGSWsk[N-i] = modulus - typename Element::Integer(1);
		}
		else{
			newRGSWsk[N-i] = typename Element::Integer(1);
		}
	}

	newRGSWsk.SwitchFormat();
	rgswSK->SetSecretKey(std::move(newRGSWsk));

	auto result = RGSWOps<Element>::KeySwitchGen(sk, rgswSK);

	return std::move(result);

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::BootStrapKeySwitchGenBV(const std::shared_ptr<RGSWSecretKey<Element>> sk, const NativeVector &lweSK){
	//sk is the RGSW type secret key used in bootstrapping
	//lweSK is the final secret for the GSW ciphertext
	//this code takes into account a ternary distribution
	//in lwe secret key.

	const auto cryptoParams = sk->GetCryptoParameters();
	auto elementParams = cryptoParams->GetElementParams();
	usint N = elementParams->GetRingDimension();
	const auto &modulus = elementParams->GetModulus();

	auto rgswSK = std::make_shared<RGSWSecretKey<Element>>(cryptoParams);
	Element newRGSWsk(elementParams, COEFFICIENT, true);

	usint dim = lweSK.GetLength(); // lwe/gsw length

	newRGSWsk[0] = (lweSK[0] == NativeInteger(0) || lweSK[0] == NativeInteger(1)) ?
			typename Element::Integer(lweSK[0].ConvertToInt()) : modulus - typename Element::Integer(1);
	for(usint i=1; i < dim ; i++){
		if(lweSK[i] == NativeInteger(0)){
			newRGSWsk[N-i] = 0;
		}
		else if(lweSK[i] == NativeInteger(1)){
			newRGSWsk[N-i] = modulus - typename Element::Integer(1);
		}
		else{
			newRGSWsk[N-i] = typename Element::Integer(1);
		}
	}

	newRGSWsk.SwitchFormat();
	rgswSK->SetSecretKey(std::move(newRGSWsk));

	auto result = RGSWOps<Element>::KeySwitchGenBV(sk, rgswSK);

	return std::move(result);
}

template <class Element>
GridCipherTypeGSW<Element> RGSWOps<Element>::GridCipherGSWClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, std::vector<Element> &m){
	GridCipherTypeGSW<Element> result;

	for (usint i = 0; i < m.size(); i++) {
		auto cipherGSW = RGSWOps<Element>::ClearEncrypt(cryptoParams, m[i]);
		result.push_back(cipherGSW);
	}

	return result;
}

template <class Element>
GridCipherTypeBV<Element> RGSWOps<Element>::GridCipherBVClearEncrypt(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, std::vector<Element> &m){
	GridCipherTypeBV<Element> result;

	for (usint i = 0; i < m.size(); i++) {
		m[i].SwitchFormat();
		Element zeroElement(cryptoParams->GetElementParams(), EVALUATION, true);
		auto cipherBV = make_shared<LWEForm<Element>>(std::move(zeroElement), std::move(m[i]));
		result.push_back(cipherBV);
	}

	return result;
}

/*template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ExtractSign(const std::shared_ptr<LWEForm<Element>> cipher, const shared_ptr<LPCryptoParameters<Element>> cryptoParams){
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);

	auto result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();
}*/

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ExtractCarryOver(std::shared_ptr<RGSWCiphertext<Element>> cipher){
	//cipher is a sign cipher
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());
	const auto ep = cryptoParamsBGV->GetElementParams();
	auto result = make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);
	typename Element::Integer twoInverse(2);
	twoInverse = twoInverse.ModInverse(ep->GetModulus());

	usint rows = cipher->GetElements().size();
	usint l = rows >> 1;
	for (usint i = 0; i < l; i++) {
		auto aPoly( (*cipher)[i].GetA() * (*oneMinusX));
		auto bPoly( (*cipher)[i].GetB() * (*oneMinusX));
		bPoly += (*onePlusX)[i].GetB();
		aPoly *= twoInverse;
		bPoly *= twoInverse;
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}
	for (usint i = l; i < rows; i++) {
		auto aPoly( (*cipher)[i].GetA() * (*oneMinusX));
		auto bPoly( (*cipher)[i].GetB() * (*oneMinusX));
		aPoly += (*onePlusX)[i].GetA();
		aPoly *= twoInverse;
		bPoly *= twoInverse;
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}
	return result;
}

template <class Element>
void RGSWOps<Element>::InitializeStaticVariables(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, usint gridSize, const NativeInteger &qLWE){
	auto ep = cryptoParams->GetElementParams();
	const auto &modulus = ep->GetModulus();
	usint N = ep->GetRingDimension();
	usint NBits = log2(N);
	usint qBits = qLWE.GetMSB() / gridSize;
	usint oneIdx = 1 << (NBits - qBits);
	auto nInverse = typename Element::Integer(N);
	nInverse = nInverse.ModInverse(modulus);

	oneMinusX = make_shared<Element>(ep, COEFFICIENT, true);
	(*oneMinusX)[0] = typename Element::Integer(1);
	(*oneMinusX)[oneIdx] = modulus - typename Element::Integer(1);
	oneMinusX->SwitchFormat();

	Element onePlusXElement(ep, COEFFICIENT, true);
	onePlusXElement[0] = typename Element::Integer(1);
	onePlusXElement[oneIdx] = typename Element::Integer(1);

	onePlusX = RGSWOps<Element>::ClearEncrypt(cryptoParams, onePlusXElement);

	Element nInverseElement(ep, COEFFICIENT, true);
	nInverseElement[0] = nInverse;
	logNInverseCipher = RGSWOps<Element>::ClearEncrypt(cryptoParams, nInverseElement);

}

template <class Element>
void RGSWOps<Element>::GeneratePowerCache(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, usint ell){
	auto ep = cryptoParams->GetElementParams();
	Element one(ep, COEFFICIENT, true);
	auto oneInt = typename Element::Integer(1);
	one[0] = oneInt;
	one.SwitchFormat();

	for(usint i=0; i< ell; i++){
		auto mssg = one * (oneInt << i);
		mssg.SwitchFormat();
		auto powerCipher = RGSWOps<Element>::ClearEncrypt(cryptoParams, mssg);
		rgswPowerCache.push_back(powerCipher);
	}
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Automorph(const std::shared_ptr<RGSWCiphertext<Element>> cipher, usint morphIdx){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());

	auto result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	usint rows = cipher->GetElements().size();

	for (usint i = 0; i < rows; i++) {
		auto aPoly = std::move(Automorph((*cipher)[i].GetA(),morphIdx));
		auto bPoly = std::move(Automorph((*cipher)[i].GetB(),morphIdx));
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	return result;
}

template <class Element>
std::shared_ptr<LWEForm<Element>> RGSWOps<Element>::Automorph(const std::shared_ptr<LWEForm<Element>> cipher, usint morphIdx){

	auto aPoly = std::move(Automorph(cipher->GetA(), morphIdx));
	auto bPoly = std::move(Automorph(cipher->GetB(), morphIdx));

	auto result = std::make_shared<LWEForm<Element>>(std::move(aPoly), std::move(bPoly));

	return result;
}

template <class Element>
Element RGSWOps<Element>::Automorph(const Element &a, usint morphIdx){
	Element result(a);

	usint n = a.GetLength();
	usint m = a.GetCyclotomicOrder();

	if (morphIdx % 2 == 0) {
		cout << "automorphism doesnt work on even numbers \n";
		throw std::runtime_error("provide a odd index value for automorphism\n");
	}

	for (usint i = 0; i < n; i++) {
		usint totValue = i * 2 + 1;
		totValue = (totValue * morphIdx) % m;
		usint rotIdx = (totValue - 1) / 2;
		result[i] = a[rotIdx];
	}

	return std::move(result);
}

template <class Element>
shared_ptr<RGSWSecretKey<Element>> RGSWOps<Element>::GetMorphedSecretkey(const shared_ptr<RGSWSecretKey<Element>> sk, usint morphIdx){
	auto cryptoParams = sk->GetCryptoParameters();
	auto result = make_shared<RGSWSecretKey<Element>>(cryptoParams);

	auto &skElement = sk->GetSecretKey();
	auto skMorphedElement = Automorph(skElement, morphIdx);
	result->SetSecretKey(std::move(skMorphedElement));

	return result;
}


}
#endif
