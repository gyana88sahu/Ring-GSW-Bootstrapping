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
void multExperiment(usint r, usint cyclo, usint bits);

int main(int argc, char *argv[]){

	if(argc!=4){
		cout << "This program takes in command line input of [relinWindow cyclotomicNumber bitlength]\n";
		cout << "Rerun program with correct input, now exiting program \n";
		return -1;
	}
	usint r = atoi(argv[1]);
	usint cyclo = atoi(argv[2]);
	usint bits = atoi(argv[3]);

	multExperiment<NativePoly>(r, cyclo, bits);

}

template <class Element>
void multExperiment(usint r, usint cyclo, usint bits){

	NativeInteger p(5);

	//parameter for RGSW Bootstrapping
	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>( p.ConvertToInt(), r, cyclo, bits, "./demo/parameters");
	auto ep = cryptoParamRGSW->GetElementParams();

	auto kp = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	typename Element::TugType tug;

	Element test1(tug, ep , COEFFICIENT);

	Element test2(tug, ep , COEFFICIENT);

	auto testCipher1 = RGSWOps<Element>::Encrypt(*kp.publicKey, test1);
	auto testCipher2 = RGSWOps<Element>::Encrypt(*kp.publicKey, test2);

	auto mult = RGSWOps<Element>::Multiply(testCipher1, testCipher2);

	auto testPtxt = RGSWOps<Element>::Decrypt(mult, kp.secretKey);

	cout << testPtxt << '\n';

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
