#include "palisadecore.h"
#include "../src/ISLWE.cpp"
#include "cryptocontext.h"
#include "../src/gsw-impl.cpp"
#include <numeric>
#include <functional>
//#include "../src/CryptoTree.h"


using namespace lbcrypto;
using namespace std;

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q);

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message,typename Element::Integer &q);

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(usint pMod, usint r, usint cyclo, usint bits, string fileName);

template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m, usint r, usint cyclo, usint bits);

template <class Element>
void runConvolutionTest(usint m, usint r, usint bits);

template <class Element>
Element GenerateAggregationVector(const shared_ptr<LPCryptoParameters<Element>> cpr);

template <class Element>
Element GenerateTestingVector(const shared_ptr<LPCryptoParameters<Element>> cpr);

template <class Element>
shared_ptr<ILWECiphertext> ConvertToSLWE(const std::shared_ptr<RGSWCiphertext<Element>> rgswCipher,shared_ptr<ILWEParams> params);

template <class Element>
usint CheckLWE(shared_ptr<ILWECiphertext> lweCipher, shared_ptr<RGSWSecretKey<Element>> ringSK);

int main(int argc, char *argv[]){

	if(argc!=5){
		cout << "This program takes in command line input of [message relinWindow cyclotomicNumber bitlength]\n";
		cout << "Rerun program with correct input, now exiting program \n";
		return -1;
	}
	usint m = atoi(argv[1]);
	usint r = atoi(argv[2]);
	usint cyclo = atoi(argv[3]);
	usint bits = atoi(argv[4]);

	runSingleCiphertextBootstrappingExperiment<NativePoly>(m, r, cyclo, bits);
	//runConvolutionTest<NativePoly>(m, r, bits);

	return 0;
}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	const auto& modulus = elemParams->GetModulus();
	usint m = elemParams->GetCyclotomicOrder();
	usint N = elemParams->GetRingDimension(); //ring dimension
	Element result(elemParams, COEFFICIENT, true);

	usint idx = (m/q)*message; //idx is between 0 to 2N-1

	if(idx>N-1){
		idx = idx%N;
		result[idx] = modulus - typename Element::Integer(1);
	}
	else{
		result[idx] = typename Element::Integer(1);
	}

	return std::move(result);
}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message, typename Element::Integer &q){
	//message is in Zq
	return std::move(GetEncoding<Element>(cryptoParams, message.ConvertToInt(), q.ConvertToInt()));
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

template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m, usint r, usint cyclo, usint bits){
	//m should be in Zp
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 500;
	m = m%p.ConvertToInt();

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	auto tug = make_shared<NativePoly::TugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);
	params->SetTernaryUniformGenerator(tug);

	std::cout << "starting standard LWE Key Generation "<< '\n';
	double start = currentDateTime();
	auto kp = ISLWEOps::KeyGen(params);
	double end = currentDateTime();
	std::cout << "standard LWE Key Genetation took "<< (end - start) <<" ms to finish \n\n";

	//std::cout << "printing LWE secret key \n" << kp.secretkey->GetSKElement() << '\n';

	std::cout << "starting standard LWE encryption algorithm and encrypting message m = "<< m << '\n';
	start = currentDateTime();
	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);
	end = currentDateTime();
	std::cout << "standard LWE Encryption took "<< (end - start) <<" ms to finish\n";
	//#############Integer-LWE ends here##############

	//Initialize ciphertext to b
	auto a = cipher->GetA();
	auto b = cipher->GetB();
	/*std::cout << "printing a vector " << a << '\n';
	std::cout << "printing b vector " << b << '\n';*/

	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>(p.ConvertToInt(), r, cyclo, bits, "./demo/parameters");

	//create beta value, beta = 2^-1Mod(p)
/*	NativeInteger beta(2);
	NativeInteger ringP = cryptoParamRGSW->GetPlaintextModulus();
	beta = beta.ModInverse(ringP);*/


	// Initialize the public key containers.
	usint N = cryptoParamRGSW->GetElementParams()->GetRingDimension();
	auto &qRGSW = cryptoParamRGSW->GetElementParams()->GetModulus();
	typename Element::Integer neg(qRGSW - 1 );
	Element NSub(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	NSub[0] = qRGSW - N;
	NSub.SwitchFormat();
	RGSWOps<Element>::SetOneCipher(cryptoParamRGSW);
	auto aggVector = GenerateAggregationVector(cryptoParamRGSW);
	auto testingVector = GenerateTestingVector(cryptoParamRGSW);
	Element unity(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	for(usint i=0; i<N;i++){
		unity[i] = 1;
	}
	unity.SwitchFormat();

	std::cout << "starting ring GSW scheme Key Genetation \n\n";
	start = currentDateTime();
	RGSWKeyPair<Element> kpRGSW = RGSWOps<Element>::KeyGen(cryptoParamRGSW);
	end = currentDateTime();
	std::cout << "ring GSW scheme Key Generation took "<< (end - start) <<" ms to finish\n\n";

	//create keygen for switching to lwe key
	std::cout << "starting generation of Key-Switch Matrix \n\n";
	start = currentDateTime();
	auto keySwitchBV = RGSWOps<Element>::BootStrapKeySwitchGenBV(kpRGSW.secretKey, kp.secretkey->GetSKElement());
	end = currentDateTime();
	std::cout << "finished generation of Key-Switch Matrix \n\n";
	std::cout << "Key-Switch Matrix Generation took "<< (end - start) <<" ms to finish\n\n";

	//Initialize masking Key Gen BV
	std::cout << "starting masking Key Genetation "<< '\n';
	start = currentDateTime();
	RGSWOps<Element>::InitializeMaskKeyBV(kpRGSW);
	end = currentDateTime();
	std::cout << "masking Key Genetation took "<< (end - start) <<" ms to finish\n\n";


	std::cout << "Generating bootstrapping key, will take time...\n";
	std::cout << "Get a coffee in the meantime...\n";
	start = currentDateTime();
	auto bootKey = ISLWEOps::BootstrappingKeyGen<Element>(*kp.secretkey, *kpRGSW.publicKey);
	end = currentDateTime();
	std::cout << "Finished bootstrapping key gen\n";
	std::cout << "Bootstrapping Key Generation took "<< (end - start) <<" ms to finish\n\n";


	start = currentDateTime();
	auto bEncoding = GetEncoding<Element>(cryptoParamRGSW, b.ConvertToInt(), q.ConvertToInt());
	//cout << bEncoding << '\n';
	bEncoding.SwitchFormat();
	bEncoding *= testingVector;
	Element zeroElement(cryptoParamRGSW->GetElementParams(), EVALUATION, true);
	auto bootCipher = make_shared<LWEForm<Element>>(std::move(zeroElement), std::move(bEncoding));
	//std::cout << "printing dummy bootCipher in exponent encoding" << RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey) << "\n";

	for (usint i = 0; i < dim; i++) {
		auto ai = a[i];
		auto minus_ai = q.ModSub(ai, q); //ai = -a[i]

		auto aiEncoding = GetEncoding<Element>(cryptoParamRGSW, ai.ConvertToInt(), q.ConvertToInt());
		auto minus_aiEncoding = GetEncoding<Element>(cryptoParamRGSW, minus_ai.ConvertToInt(), q.ConvertToInt());
		aiEncoding[0]+= neg;
		minus_aiEncoding[0]+= neg;
		aiEncoding.SwitchFormat();
		minus_aiEncoding.SwitchFormat();

		auto first = RGSWOps<Element>::ClearRingMultiply(aiEncoding, bootKey[i][0]);
		auto second = RGSWOps<Element>::ClearRingMultiply(minus_aiEncoding, bootKey[i][1]);
		RGSWOps<Element>::AddOneInPlace(first);
		RGSWOps<Element>::AddOneInPlace(second);

		RGSWOps<Element>::MultiplyInPlace(first, bootCipher);
		RGSWOps<Element>::MultiplyInPlace(second, bootCipher);

		/*//debug code starts
		{
			auto firstValue = RGSWOps<Element>::Decrypt(first, kpRGSW.secretKey);
			auto secondValue = RGSWOps<Element>::Decrypt(second, kpRGSW.secretKey);
			auto aisiValue = RGSWOps<Element>::Decrypt(aisi, kpRGSW.secretKey);
			auto bootCipherValue = RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey);
			std::cout << "printing firstValue in exponent encoding" << firstValue << "\n";
			std::cout << "printing secondValue in exponent encoding" << secondValue << "\n";
			std::cout << "printing aisi in exponent encoding" << aisiValue << "\n";
			std::cout << "printing bootCipher in exponent encoding" << bootCipherValue << "\n";
		}

		//debug code ends*/

	}

	//std::cout << "printing ciphertext in exponent encoding" << RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey) << "\n";

/*	auto finalValue = RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey);
	std::cout << finalValue << endl;*/

	bootCipher->GetB() += NSub;
	/*bootCipher->GetA().NegateSelf();
	bootCipher->GetB().NegateSelf();*/

/*	finalValue = RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey);
	std::cout << finalValue << endl;*/


	//secondary bootstrap starts
	auto gswCipher = RGSWOps<Element>::ExtractMaskedCipherAltAlt(bootCipher);

	//first Key-Switch and then ModReduce
	auto gswCipherKeySwitched = RGSWOps<Element>::KeySwitchBV(gswCipher, keySwitchBV);
	end = currentDateTime();
	std::cout << "Bootstrapping GSW Ciphertext Loop took "<< (end - start) <<" ms to finish\n\n";

	auto finalValue = RGSWOps<Element>::Decrypt(gswCipher, kpRGSW.secretKey);
	std::cout << finalValue << endl;
}

template <class Element>
Element GenerateAggregationVector(const shared_ptr<LPCryptoParameters<Element>> cpr){
	Element two(cpr->GetElementParams(),COEFFICIENT,true);

	usint N = cpr->GetElementParams()->GetRingDimension();

	two[0] = 1;
	for (usint i = 1; i < N; i++) {
		two[i] = two.GetModulus() - typename Element::Integer(1);
	}
	two.SwitchFormat();
	return std::move(two);
}

template <class Element>
shared_ptr<ILWECiphertext> ConvertToSLWE(const std::shared_ptr<RGSWCiphertext<Element>> rgswCipher,shared_ptr<ILWEParams> params){

	
	auto aRing = rgswCipher->GetElements().at(0).GetA();
	auto bRing = rgswCipher->GetElements().at(0).GetB();
	aRing.SwitchFormat(); //in coeff
	bRing.SwitchFormat(); //in coeff
	NativeVector aSLWE(aRing.GetRingDimension(),NativeInteger(aRing.GetModulus()));
	NativeInteger bSLWE(bRing[0]);

	aSLWE[0] = NativeInteger(aRing[0]);
	auto modulus = aRing.GetModulus();
	auto N = aRing.GetRingDimension();
	for (usint i = 1; i < N; i++) {
		auto val = modulus.ModSub(aRing[N-i],modulus);
		aSLWE[i] = NativeInteger(val);
	}

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(NativeInteger(aRing.GetModulus()));
	NativeInteger p(rgswCipher->GetCryptoParameters()->GetPlaintextModulus());
	shared_ptr<ILWEParams> paramsFromRGSW = make_shared < ILWEParams > (p, NativeInteger(aRing.GetModulus()), aRing.GetLength());

	shared_ptr<ILWECiphertext> result = make_shared<ILWECiphertext>(paramsFromRGSW);

	result->SetA(aSLWE);
	result->SetB(bSLWE);
	return result;
}

template <class Element>
usint CheckLWE(shared_ptr<ILWECiphertext> lweCipher, shared_ptr<RGSWSecretKey<Element>> ringSK){
	const auto &a = lweCipher->GetA();
	const auto &s = ringSK->GetSecretKey();
	//auto modulus = a.GetModulus(); //modulus is same for both a and s
	
	usint N = a.GetLength();
	NativeVector sVec(N,s.GetModulus());
	for(usint i=0; i < N; i++){
		sVec[i] = s[i];
	}
	

	ILWESecretKey newSK(lweCipher->GetLWEParams());
	newSK.SetSKElement(sVec);

	usint message = ISLWEOps::Decrypt(lweCipher,newSK);
	cout << "message is "<< message << "\n";

	//form new parameter set
	NativeInteger qDash(512);
	auto dggDash = make_shared<NativePoly::DggType>(2.0);
	auto dugDash = make_shared<NativePoly::DugType>();
	dugDash->SetModulus(qDash);
	shared_ptr<ILWEParams> paramDash = make_shared<ILWEParams>(lweCipher->GetLWEParams()->GetPlaintextModulus(),qDash,N);
	paramDash->SetDiscreteUniformGenerator(dugDash);
	paramDash->SetDiscreteGaussianGenerator(dggDash);

	//mod reduce the cipgertext
	auto lweCipherReduced = ISLWEOps::ModSwitch(lweCipher,qDash);
	ILWESecretKey newSKModReduced(paramDash);
	auto sDash = sVec;
	sDash.SwitchModulus(qDash);
	newSKModReduced.SetSKElement(sDash);

	message = ISLWEOps::Decrypt(lweCipherReduced,newSKModReduced);
	cout << "message is "<< message << "\n";

	return 0;
}

template <class Element>
void runConvolutionTest(usint m, usint r, usint bits){
	NativeInteger q(512);
	NativeInteger p(5);

	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>(r, bits, "./demo/parameters");
	usint N = cryptoParamRGSW->GetElementParams()->GetRingDimension();
	auto &Q = cryptoParamRGSW->GetElementParams()->GetModulus();

	//unity element generation
	Element unity(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	for (usint i = 0; i < N; i++) {
		unity[i] = 1;
	}
	unity.SwitchFormat();

	//aggregation element generation
	Element agg(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	for (usint i = 1; i < N; i++) {
		agg[i] = Q-1;
	}
	agg[0] = 1;
	agg.SwitchFormat();

	//keyGen
	auto kp = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	//encode message
	auto mEncoding = GetEncoding<Element>(cryptoParamRGSW, m, q.ConvertToInt());

	//encrypt message
	auto mCipher = RGSWOps<Element>::Encrypt(*kp.publicKey, mEncoding);

	//multiply it with unity element
	for (usint i = 0; i < mCipher->GetElements().size(); i++) {
		(*mCipher)[i].GetA() *= unity;
		(*mCipher)[i].GetB() *= unity;
	}

	//decrypt and show result
	auto finalValue = RGSWOps<Element>::Decrypt(mCipher, kp.secretKey);
	std::cout << finalValue << endl;

	//multiply it with aggregation element
	for (usint i = 0; i < mCipher->GetElements().size(); i++) {
		(*mCipher)[i].GetA() *= agg;
		(*mCipher)[i].GetB() *= agg;
	}

	//decrypt and show result
	finalValue = RGSWOps<Element>::Decrypt(mCipher, kp.secretKey);
	std::cout << finalValue << endl;
}

template <class Element>
Element GenerateTestingVector(const shared_ptr<LPCryptoParameters<Element>> cpr){

	Element unity(cpr->GetElementParams(),COEFFICIENT,true);
	Element two(cpr->GetElementParams(),COEFFICIENT,true);
	auto &modulus = cpr->GetElementParams()->GetModulus();
	auto &p = cpr->GetPlaintextModulus();
	usint pHalf = p >> 1;

	usint N = cpr->GetElementParams()->GetRingDimension();

	two[0] = 1;
	unity[0] = 1;
	for (usint i = 1; i < N; i++) {
		two[i] = two.GetModulus() - typename Element::Integer(1);
		unity[i] = 1;
	}
	two.SwitchFormat();
	unity.SwitchFormat();

	Element testingVector(two*unity);
	testingVector.SwitchFormat();
	auto result = testingVector.Mod(p);
	//cout << "printing after mod \n" << result << "\n\n";
	for (usint i = 0; i < N; i++) {
		if (result[i] > pHalf) {
			testingVector[i] = (modulus + testingVector[i]) - p;
		}
		else{
			testingVector[i] = result[i];
		}
	}
	testingVector.SwitchFormat();

	return std::move(testingVector);
}




