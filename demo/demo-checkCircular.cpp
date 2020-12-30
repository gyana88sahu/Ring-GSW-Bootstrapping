#include "palisade.h"
#include "../src/ISLWE.cpp"
#include "cryptocontext.h"
#include "../src/gsw-impl.cpp"
#include <numeric>
#include <functional>

using namespace lbcrypto;
using namespace std;

template <class Element>
void CheckEncryptionMask(usint r, usint cyclo, usint bits);

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(usint pMod, usint r, usint cyclo, usint bits, string fileName);

int main(int argc, char *argv[]){

	if(argc!=4){
		cout << "This program takes in command line input of [relinWindow cyclotomicNumber bitlength]\n";
		cout << "Rerun program with correct input, now exiting program \n";
		return -1;
	}

	usint r = atoi(argv[1]);
	usint cyclo = atoi(argv[2]);
	usint bits = atoi(argv[3]);

	CheckEncryptionMask<NativePoly>(r, cyclo, bits);

	return 0;
}

template <class Element>
void CheckEncryptionMask(usint r, usint cyclo, usint bits){

	typename Element::Integer p(5);

	//parameter for RGSW Bootstrapping
	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>( p.ConvertToInt(), r, cyclo, bits, "./demo/parameters");
	auto ep = cryptoParamRGSW->GetElementParams();

	auto kp = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	RGSWOps<Element>::InitializeCircularKey(kp);

	Element message(ep, COEFFICIENT, true);
	message = {2,3,4,1,2,4};
	cout << "message is \n" << message << '\n';

	auto cipher = RGSWOps<Element>::Encrypt(*kp.publicKey, message);

	auto lwe = make_shared<LWEForm<Element>>((*cipher)[0].GetA(), (*cipher)[0].GetB());

	auto cipherMasked = RGSWOps<Element>::ExtractMaskedCipherAlt(lwe);

	auto ptxt = RGSWOps<Element>::Decrypt(cipherMasked, kp.secretKey);
	cout << ptxt << "\n\n";

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

