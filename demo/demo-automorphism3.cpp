#include "palisade.h"
#include "scheme/rlwe.h"
#include "../src/gsw-impl.cpp"


using namespace lbcrypto;
using namespace std;

template <class Element>
Element automorph(const Element &poly, usint morphIdx);

template <class Element>
shared_ptr<RGSWSecretKey<Element>> GetMorphedSecretkey(const shared_ptr<RGSWSecretKey<Element>> sk, usint morphIdx);

template <class Element>
shared_ptr<RGSWCiphertext<Element>> GetMorphedCiphertext(const shared_ptr<RGSWCiphertext<Element>> cipher, usint morphIdx);

int main(int argc, char *argv[]){

	/*
	 * This example shows how to multiply a ciphertext
	 * which is encoded in root of unity with an odd integer within the
	 * cyclotomic number m
	 */
	/*if(argc!=3){
		cout << "Must Enter automorphism index and message index \n";
		return -1;
	}*/

	using T = NativePoly;

	/*usint aIdx = atoi(argv[1]);
	usint mssgIdx = atoi(argv[2]);*/
	usint aIdx0 = 9;
	usint aIdx1 = 5;
	usint aIdx2 = 3;

	usint m = 16;
		//usint n = m/2;
	typename T::Integer q("35184372088961");
	typename T::Integer rootOfUnity("33098764372315");
	usint plaintextModulus = 5;
	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;
	auto ep = make_shared<typename T::Params>(m, q, rootOfUnity);
	auto cp = make_shared < LPCryptoParametersBGV<T> > (ep, plaintextModulus, stdDev, assm, sL, relinWindow, RLWE, 1);
	auto nInverse = typename T::Integer(m/2);
	nInverse = nInverse.ModInverse(q);
	T nInverseElement(ep, COEFFICIENT, true);
	nInverseElement[0] = nInverse;
	auto nInverseCipher = RGSWOps<T>::ClearEncrypt(cp, nInverseElement);

	auto kp = RGSWOps<T>::KeyGen(cp);
	auto skMorphed0 = GetMorphedSecretkey(kp.secretKey, aIdx0);
	auto skMorphed1 = GetMorphedSecretkey(kp.secretKey, aIdx1);
	auto skMorphed2 = GetMorphedSecretkey(kp.secretKey, aIdx2);

	auto ksm0 = RGSWOps<T>::KeySwitchGen(skMorphed0, kp.secretKey);
	auto ksm1 = RGSWOps<T>::KeySwitchGen(skMorphed1, kp.secretKey);
	auto ksm2 = RGSWOps<T>::KeySwitchGen(skMorphed2, kp.secretKey);


	T messageEl(ep, COEFFICIENT,true);
	messageEl[0] = q-1;
	messageEl[1] = 1;
	messageEl[2] = 3;
	messageEl[3] = 1;
	messageEl[4] = 2;
	messageEl[5] = 1;
	messageEl[6] = 1;
	messageEl[7] = 0;
	auto cipher = RGSWOps<T>::Encrypt(*kp.publicKey, messageEl);

	auto cipherMorphed = GetMorphedCiphertext(cipher, aIdx0);
	cipherMorphed = RGSWOps<T>::KeySwitch(cipherMorphed, ksm0);
	{
		cout << "printing cipherMorphed after iteration 1\n\n";
		auto ptxt = RGSWOps<T>::Decrypt(cipherMorphed, kp.secretKey);
		cout << ptxt << "\n";
	}

	auto cipherAdd = RGSWOps<T>::Add(cipherMorphed, cipher);


	cipherMorphed = GetMorphedCiphertext(cipherAdd, aIdx1);
	cipherMorphed = RGSWOps<T>::KeySwitch(cipherMorphed, ksm1);
	{
		cout << "printing cipherMorphed after iteration 2\n\n";
		auto ptxt = RGSWOps<T>::Decrypt(cipherMorphed, kp.secretKey);
		cout << ptxt << "\n";
	}
	cipherAdd = RGSWOps<T>::Add(cipherMorphed, cipherAdd);

	cipherMorphed = GetMorphedCiphertext(cipherAdd, aIdx2);
	cipherMorphed = RGSWOps<T>::KeySwitch(cipherMorphed, ksm2);
	{
		cout << "printing cipherMorphed after iteration 3\n\n";
		auto ptxt = RGSWOps<T>::Decrypt(cipherMorphed, kp.secretKey);
		cout << ptxt << "\n";
	}
	cipherAdd = RGSWOps<T>::Add(cipherMorphed, cipherAdd);
	cipherAdd = RGSWOps<T>::Multiply(nInverseCipher, cipherAdd);

	auto incrResult = RGSWOps<T>::Decrypt(cipher, kp.secretKey);
	//auto result = RGSWOps<T>::Decrypt(cipherMorphed, kp.secretKey);
	auto resultAdd = RGSWOps<T>::Decrypt(cipherAdd, kp.secretKey);
	cout << incrResult << '\n';
	//cout << result << '\n';
	cout << resultAdd << '\n';

}

void fftTest(const std::vector<usint> &vals){
	using T = NativePoly;
	usint m = 16;
	//usint n = m/2;
	typename T::Integer q("4194353");
	typename T::Integer rootOfUnity("4062183");
	usint plaintextModulus = 5;
	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;
	auto ep = make_shared<typename T::Params>(m, q, rootOfUnity);
	auto cp = make_shared < LPCryptoParametersBGV<T> > (ep, plaintextModulus, stdDev, assm, sL, relinWindow, RLWE, 1);

	T el0(ep, COEFFICIENT, true);
	for (usint i = 0; i < vals.size(); i++) {
		el0[i] = typename T::Integer(vals[i]);
	}
	el0.SwitchFormat();
	cout << el0 << '\n';
}


template <class Element>
shared_ptr<RGSWSecretKey<Element>> GetMorphedSecretkey(const shared_ptr<RGSWSecretKey<Element>> sk, usint morphIdx){
	auto cryptoParams = sk->GetCryptoParameters();
	auto result = make_shared<RGSWSecretKey<Element>>(cryptoParams);

	auto skElement(sk->GetSecretKey());
	auto skMorphedElement = automorph(skElement, morphIdx);
	result->SetSecretKey(std::move(skMorphedElement));

	return result;
}

template <class Element>
shared_ptr<RGSWCiphertext<Element>> GetMorphedCiphertext(const shared_ptr<RGSWCiphertext<Element>> cipher, usint morphIdx){
	auto cryptoParams = cipher->GetCryptoParameters();
	auto result = make_shared<RGSWCiphertext<Element>>(cryptoParams);

	usint rows = cipher->GetElements().size();
	for(usint i=0; i<rows;i++){
		auto aPoly((*cipher)[i].GetA());
		auto bPoly((*cipher)[i].GetB());
		aPoly = automorph(aPoly, morphIdx);
		bPoly = automorph(bPoly, morphIdx);
		result->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	return result;
}

template <class Element>
Element automorph(const Element &poly, usint morphIdx){

	Element result(poly);

	usint m = poly.GetCyclotomicOrder();
	usint n = poly.GetLength();

	if(morphIdx%2==0){
		cout << "automorphism doesnt work on even numbers \n";
		throw std::runtime_error("provide a odd index value for automorphism\n");
	}

	for(usint i=0; i<n;i++){
		usint totValue = i*2 +1;
		totValue = (totValue*morphIdx)%m;
		usint rotIdx = (totValue-1)/2;
		result[i] = poly[rotIdx];
	}

	return std::move(result);
}



