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
void maskingExperiment(usint r, usint cyclo, usint bits);

int main(int argc, char *argv[]){

	if(argc!=4){
		cout << "This program takes in command line input of [relinWindow cyclotomicNumber bitlength]\n";
		cout << "Rerun program with correct input, now exiting program \n";
		return -1;
	}
	usint r = atoi(argv[1]);
	usint cyclo = atoi(argv[2]);
	usint bits = atoi(argv[3]);

	maskingExperiment<NativePoly>(r, cyclo, bits);

}

template <class Element>
void maskingExperiment(usint r, usint cyclo, usint bits){

	NativeInteger q(512*512);
	NativeInteger p(5);

	//parameter for RGSW Bootstrapping
	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>( p.ConvertToInt(), r, cyclo, bits, "./demo/parameters");
	auto ep = cryptoParamRGSW->GetElementParams();
	auto &modulus = ep->GetModulus();
	usint N = ep->GetRingDimension();
	usint NBits = log2(N);
	auto nInverse = typename Element::Integer(N);
	nInverse = nInverse.ModInverse(modulus);

	auto kp = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	RGSWOps<Element>::InitializeStaticVariables(cryptoParamRGSW, 2, q);

	RGSWOps<Element>::InitializeMaskKey(kp);

	typename Element::TugType tug;

	Element test(tug, ep , COEFFICIENT);

	cout << "printing values before masking \n\n";

	cout << test << '\n';

	//test *= nInverse;

	cout << "printing after test \n\n"<< test << '\n';

	auto testCipher = RGSWOps<Element>::Encrypt(*kp.publicKey, test);

	//testCipher = RGSWOps<Element>::ExtractMaskedCipherAltAlt(testCipher);
	auto cipherAdd = testCipher;
	for (usint i = 0; i < NBits; i++) {
		usint idx = 1 << i;
		usint aIdx = N / idx + 1;
		auto cipherMorphed = RGSWOps<Element>::Automorph(cipherAdd, aIdx);
		cipherMorphed = RGSWOps<Element>::KeySwitch(cipherMorphed, RGSWOps<Element>::maskKeysGSW[i]);
		//cipherMorphed = RGSWOps<Element>::KeySwitchBV(cipherMorphed, maskKeysBV[i]);
		cipherAdd = RGSWOps<Element>::Add(cipherMorphed, cipherAdd);
		cout << "printing ciphertext after iteration " << i << "\n\n";
		auto cipherAddPtxt = RGSWOps<Element>::Decrypt(cipherAdd, kp.secretKey);
		cout << cipherAddPtxt << "\n";
	}

	testCipher = cipherAdd;

	auto testPtxt = RGSWOps<Element>::Decrypt(testCipher, kp.secretKey);

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
