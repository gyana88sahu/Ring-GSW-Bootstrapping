#include "palisade.h"
#include "../src/ISLWE.cpp"
#include "cryptocontext.h"
#include "../src/gsw-impl.cpp"
#include <numeric>
#include <functional>

using namespace lbcrypto;
using namespace std;

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(usint pMod, usint r, usint cyclo, usint bits, string fileName);

template <class Element>
Element MultiplyInInverseDomain(const Element &a, const Element &b);

int main(){

	using T = NativePoly;
	auto param = GetRGSWCryptoParams<T>(5, 1, 512, 40, "./demo/parameters");

	auto ep = param->GetElementParams();
	//dummy
	T dummy(ep, COEFFICIENT, true);
	dummy.SwitchFormat();
	dummy.SwitchFormat();

	//a = {1,2,3,4}
	//b = {2,4,0,3}
	T a(ep, EVALUATION, true);
	a = {1,2,3,4};

	T b(ep, EVALUATION, true);
	b = {2,0,0,0};

	a.SwitchFormat();
	b.SwitchFormat();

	T m0(ep, COEFFICIENT, true);

	T m1(ep, COEFFICIENT, true);

	usint N = ep->GetRingDimension();

	for(usint i=0; i<N; i++){
		m0[i] = a[i];
		m1[i] = b[i];
	}

	auto kp = RGSWOps<T>::KeyGen(param);

	auto acipher = RGSWOps<T>::Encrypt(*kp.publicKey, m0);
	auto bcipher = RGSWOps<T>::Encrypt(*kp.publicKey, m1);
	auto ccipher = RGSWOps<T>::Multiply(acipher, bcipher);

	auto cplain = (*ccipher)[0].GetB() - (*ccipher)[0].GetA()*kp.secretKey->GetSecretKey();
	cout << cplain << endl;
	T cmock(ep, COEFFICIENT, true);
	for(usint i=0; i<N; i++){
		cmock[i] = cplain[i];
	}
	cmock.SwitchFormat();
	cout << cmock << endl;


	return 0;
}


template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(usint pMod, usint r, usint cyclo, usint bits, string fileName){
	ifstream file(fileName);
	shared_ptr<LPCryptoParameters<Element>> params = nullptr;
	if(!file.is_open()){
		cout << "file could not be opened\n";
		return params;
	}
	usint m = cyclo;
	usint p = pMod;
	PlaintextModulus modulusP(p);

	string line;
	while (getline(file, line))
	{
		istringstream iss(line);
		string first, second, third;
		iss >> first;
		if(first=="params"){
			iss >> second;
			iss >> third;
			if(second==to_string(m) && third==to_string(bits)){
				getline(file,line);
				istringstream iss2(line);
				string modString, rootString;
				iss2 >> modString;
				iss2 >> rootString;
				float stdDev = 4;
				float assm = 9;//assuranceMeasure
				float sL = 1.006;//securityLevel
				usint relinWindow = r;
				typename Element::Integer modulus(modString);
				typename Element::Integer rootOfUnity(rootString);
				auto ep = make_shared < typename Element::Params > (m, modulus, rootOfUnity);
				params = make_shared<LPCryptoParametersBGV<Element>> (ep, modulusP, stdDev, assm, sL, relinWindow, RLWE, 1);
			}
		}
	}

	file.close();
	return params;
}


