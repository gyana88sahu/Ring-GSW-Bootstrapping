#ifndef LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C
#define LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C

#include "ISLWE.h"

namespace lbcrypto{

template <class Element>
Element GetEncoding1(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	const auto& modulus = elemParams->GetModulus();
	usint p = cryptoParams->GetPlaintextModulus();
	usint m = elemParams->GetCyclotomicOrder();
	usint N = elemParams->GetRingDimension(); //ring dimension

	typename Element::Vector vec(N, modulus);

	usint idx = (m/q)*message; //idx is between 0 to 2N-1

	if(idx>N-1){
		idx = idx%N;
		vec[idx] = typename Element::Integer(p-1);
	}
	else{
		vec[idx] = typename Element::Integer(1);
	}

	Element result(cryptoParams->GetElementParams(),COEFFICIENT,true);
	result.SetValues(vec, COEFFICIENT);

	return std::move(result);
}

template <class Element>
Element GetEncoding1(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message, typename Element::Integer &q){
	//message is in Zq
	return GetEncoding1<Element>(cryptoParams, message.ConvertToInt(), q.ConvertToInt());
}

inline NativeInteger Sum1(const NativeVector &vec){
	NativeInteger ans(0);
	for(usint i=0;i<vec.GetLength();i++){
		ans+= vec[i];
		ans = ans.Mod(vec.GetModulus());
	}
	return ans.Mod(vec.GetModulus());
}

inline ILWEKeyPair ISLWEOps::KeyGen(const shared_ptr<ILWEParams> &param, string gen) {
	ILWEKeyPair kp(param);

	usint dim = param->GetDimension();
	auto modulus = param->GetModulus();
	auto p = param->GetPlaintextModulus();
	//auto s = param->GetDiscreteGaussianGenerator().GenerateVector(dim,modulus);
	auto s = param->GetTernaryUniformGenerator().GenerateVector(dim,modulus);
	if(gen=="BINARY")
		s = param->GetBinaryUniformGenerator().GenerateVector(dim,modulus);

	auto a = param->GetDiscreteUniformGenerator().GenerateVector(dim);
	auto e = param->GetDiscreteGaussianGenerator().GenerateInteger(modulus);
	//make e positive
	if(e>(modulus>>1)){
		e = modulus.ModSub(e,modulus);
	}

	kp.secretkey->SetSKElement(s);
	kp.publickey->SetA(a);

	NativeInteger b(0);

	b = p*e;
	std::cout << "Noise in ISLWE is "<<b<<'\n';
	b+= Sum1(a*s);
	b = b.Mod(a.GetModulus());
	kp.publickey->SetB(b);

	return kp;
}

inline shared_ptr<ILWECiphertext> ISLWEOps::Encrypt(const ILWEPublicKey &pk, usint m) {

	auto result = make_shared<ILWECiphertext>(pk.GetLWEParams());

	auto q = pk.GetLWEParams()->GetModulus();

	NativeInteger val(m);

	val += pk.GetPKElement()->GetB();// val = a.s + p*e + m

	val = val.Mod(q); //reduce mod q

	result->SetA(pk.GetPKElement()->GetA());

	result->SetB(val);

	return result;
}

inline usint ISLWEOps::Decrypt(const shared_ptr<ILWECiphertext> cipher,const ILWESecretKey &sk) {
	auto a = cipher->GetA();
	auto b = cipher->GetB();
	auto s = sk.GetSKElement();
	auto p = sk.GetLWEParams()->GetPlaintextModulus();
	auto q = sk.GetLWEParams()->GetModulus();

	auto val = Sum1(a * s);
	val = b.ModSub(val, q); //val = b-a*s
	auto halfQ = q >> 1;
	if (val > halfQ) {
		val = val.ModSub(q, p);
	} else {
		val = val.Mod(p);
	}

	return val.ConvertToInt();
}

inline std::vector<std::vector<shared_ptr<ILWECiphertext>>> ISLWEOps::KeySwitchGen(const ILWESecretKey &sk,const ILWESecretKey &newSk,usint rKS) {

	std::vector < std::vector<shared_ptr<ILWECiphertext>> > hint;

	auto islweParams = sk.GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	auto q = islweParams->GetModulus();
	auto p = islweParams->GetPlaintextModulus();
	usint l = q.GetMSB();

	l = std::ceil((double) l / (double) rKS);

	for (usint i = 0; i < lweDim; i++) {
		auto si = sk.GetSKElement()[i];
		hint.push_back(std::vector<shared_ptr<ILWECiphertext>>());
		for (usint j = 0; j < l; j++) {
			auto powerSi = si * NativeInteger(1 << (j * rKS));
			powerSi = powerSi.Mod(q);
			//Generate ciphertext for powerSi
			auto a = islweParams->GetDiscreteUniformGenerator().GenerateVector(
					lweDim);
			auto e =
					islweParams->GetDiscreteGaussianGenerator().GenerateInteger(
							q);
			//make e positive
			if (e > (q >> 1)) {
				e = q.ModSub(e, q);
			}
			NativeInteger b(0);

			b = p * e;
			//std::cout << "Noise in ISLWE is " << b << '\n';
			b += Sum1(a * newSk.GetSKElement());
			b += powerSi;
			b = b.Mod(a.GetModulus());

			auto cipher = make_shared < ILWECiphertext > (islweParams);
			cipher->SetA(a);
			cipher->SetB(b);

			hint[i].push_back(cipher);

		}
	}


	return hint;
}

inline shared_ptr<ILWECiphertext> ISLWEOps::ModSwitch(shared_ptr<ILWECiphertext> c, NativeInteger &qDash){

	auto islweParams = c->GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	auto q = islweParams->GetModulus();
	auto p = islweParams->GetPlaintextModulus();
	
	auto a = c->GetA();
	auto b = c->GetB();

	NativeVector aDash(lweDim,qDash);
	NativeInteger bDash;

	for (usint i = 0; i < lweDim; i++) {
		auto num = a[i];
		num = num*qDash;
		num = num/q;

		auto diff = (a[i].Mod(p)).ModSub(num.Mod(p),p);
		aDash[i] = num + diff;
	}

	NativeInteger num = b;
	num = num*qDash;
	num = num/q;
	auto diff = (b.Mod(p)).ModSub(num.Mod(p),p);
	bDash = num + diff;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(qDash);
	shared_ptr<ILWEParams> params = make_shared < ILWEParams > (p, qDash, lweDim);


	auto result = make_shared<ILWECiphertext>(params);

	result->SetA(aDash);
	result->SetB(bDash);

	return result;
}

template <class Element>
std::vector<std::shared_ptr<RGSWCiphertext<Element>>> ISLWEOps::BootstrappingKeyGenBinary(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk){
	std::vector<std::shared_ptr<RGSWCiphertext<Element>>> result;

	const auto cryptoParams = pk.GetCryptoParameters();

	auto islweParams = sk.GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	const auto &s = sk.GetSKElement();

	//generating for binary secret key and multiplexer approach
	for (usint i = 0; i < lweDim; i++) {
		auto val = s[i];
		if(val==NativeInteger(0) ){
			auto cipher = RGSWOps<Element>::Encrypt(pk, 0);
			result.push_back(cipher);
		}
		else { //val == 1
			auto cipher = RGSWOps<Element>::Encrypt(pk, 1);
			result.push_back(cipher);
		}

	}

	return std::move(result);
}

template <class Element>
std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> ISLWEOps::BootstrappingKeyGen(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk){
	std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> result;

	const auto cryptoParams = pk.GetCryptoParameters();

	auto islweParams = sk.GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	const auto &s = sk.GetSKElement();

	//generating for ternary secret key
	for (usint i = 0; i < lweDim; i++) {
		result.push_back(std::vector<std::shared_ptr<RGSWCiphertext<Element>>>());
		auto val = s[i];
		if(val==NativeInteger(0) ){
			auto cipher0 = RGSWOps<Element>::Encrypt(pk, 0);
			auto cipher1 = RGSWOps<Element>::Encrypt(pk, 0);
			result[i].push_back(cipher0);
			result[i].push_back(cipher1);
		}
		else if(val==NativeInteger(1)){
			auto cipher0 = RGSWOps<Element>::Encrypt(pk, 0);
			auto cipher1 = RGSWOps<Element>::Encrypt(pk, 1);
			result[i].push_back(cipher0);
			result[i].push_back(cipher1);
		}
		else{
			auto cipher0 = RGSWOps<Element>::Encrypt(pk, 1);
			auto cipher1 = RGSWOps<Element>::Encrypt(pk, 0);
			result[i].push_back(cipher0);
			result[i].push_back(cipher1);
		}

	}


	return std::move(result);
}

template <class Element>
std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> ISLWEOps::BootstrappingKeyGenAuto(const ILWESecretKey &sk, const RGSWPublicKey<Element> &pk){

	std::vector<std::vector<std::shared_ptr<RGSWCiphertext<Element>>>> result;

	const auto cryptoParams = pk.GetCryptoParameters();
	auto ep = cryptoParams->GetElementParams();
	auto &modulusRGSW = ep->GetModulus();
	auto N = ep->GetRingDimension();
	auto m = ep->GetCyclotomicOrder();
	usint NBits = log2(N);

	auto islweParams = sk.GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	const auto &s = sk.GetSKElement();
	usint modulusLWE = islweParams->GetModulus().ConvertToInt();
	usint idxFactor = m / modulusLWE;

	//generating for ternary secret key
	for (usint i = 0; i < lweDim; i++) {
		auto val = s[i].ConvertToInt();
		result.push_back(std::vector<std::shared_ptr<RGSWCiphertext<Element>>>());

		for (usint j = 0; j < NBits; j++) {
			usint power = 1 << j;
			auto valPower = (val*power)%modulusLWE;
			auto valIdx = idxFactor*valPower; // valIdx is between 0 to m-1
			Element mssg(ep, COEFFICIENT, true);
			if(valIdx>N-1){
				valIdx = valIdx%N;
				mssg[valIdx] = modulusRGSW - typename Element::Integer(1);
			}
			else{
				mssg[valIdx] = typename Element::Integer(1);
			}
			auto cipher = RGSWOps<Element>::Encrypt(pk, mssg);
			result[i].push_back(cipher);
		}
	}

	return std::move(result);
}

}


#endif
