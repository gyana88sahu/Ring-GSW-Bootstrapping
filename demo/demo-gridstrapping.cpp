#include "palisade.h"
#include "../src/ISLWE.cpp"
#include "cryptocontext.h"
#include "../src/gsw-impl.cpp"
#include <numeric>
#include <functional>

using namespace lbcrypto;
using namespace std;

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, usint message, usint q);

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, typename Element::Integer &message, typename Element::Integer &q);

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(usint pMod, usint r, usint cyclo, usint bits, string fileName);

template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m, usint r, usint cyclo, usint bits);

template <class Element>
Element GenerateTestingVector(const shared_ptr<LPCryptoParameters<Element>> cpr);

template <class Element>
std::vector<Element> GetGridEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, const NativeInteger &b, const NativeInteger &q, usint gridDim);

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

}

template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m, usint r, usint cyclo, usint bits){

	//m should be in Zp
	double start,end;
	NativeInteger q(512*512);
	NativeInteger p(5);
	usint dim = 10;
	m = m%p.ConvertToInt();
	usint gridSize = 2;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	auto tug = make_shared<NativePoly::TugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);
	params->SetTernaryUniformGenerator(tug);

	std::cout << "starting standard LWE Key Generation "<< '\n';
	start = currentDateTime();
	auto kp = ISLWEOps::KeyGen(params);
	end = currentDateTime();
	std::cout << "standard LWE Key Genetation took "<< (end - start) <<" ms to finish\n\n";

	std::cout << "starting standard LWE encryption algorithm and encrypting message m = "<< m << '\n';
	start = currentDateTime();
	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);
	end = currentDateTime();
	std::cout << "standard LWE Encryption took "<< (end - start) <<" ms to finish\n";
	//#############Integer-SLWE ends here ##############

	//Initialize ciphertext to b
	auto a = cipher->GetA();
	auto b = cipher->GetB();
	auto sk = kp.secretkey->GetSKElement();
	std::cout << "printing a vector " << a << '\n';
	std::cout << "printing b vector " << b << '\n';
	std::cout << "printing secret key vector " << sk << '\n';

	//parameter for RGSW Bootstrapping
	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>( p.ConvertToInt(), r, cyclo, bits, "./demo/parameters");

	std::cout << "starting ring GSW scheme Key Generation \n\n";
	start = currentDateTime();
	RGSWKeyPair<Element> kpRGSW = RGSWOps<Element>::KeyGen(cryptoParamRGSW);
	end = currentDateTime();
	std::cout << "ring GSW scheme Key Generation took "<< (end - start) <<" ms to finish\n\n";

	//variables needed in gridstrapping
	usint N = cryptoParamRGSW->GetElementParams()->GetRingDimension();
	auto &qRGSW = cryptoParamRGSW->GetElementParams()->GetModulus();
	auto nInverse = typename Element::Integer(N);
	nInverse = nInverse.ModInverse(qRGSW);
	typename Element::Integer neg(qRGSW - 1 );
	Element NSub(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	NSub[0] = qRGSW - N;
	NSub.SwitchFormat();
	RGSWOps<Element>::SetOneCipher(cryptoParamRGSW);
	auto testingVector = GenerateTestingVector(cryptoParamRGSW);
	Element unity(cryptoParamRGSW->GetElementParams(), COEFFICIENT, true);
	for (usint i = 0; i < N; i++) {
		unity[i] = nInverse;
	}
	unity.SwitchFormat();
	RGSWOps<Element>::InitializeStaticVariables(cryptoParamRGSW, gridSize, q);

	//Initialize mask key
	std::cout << "starting masking Key Genetation "<< '\n';
	start = currentDateTime();
	RGSWOps<Element>::InitializeMaskKey(kpRGSW);
	end = currentDateTime();
	std::cout << "masking Key Genetation took "<< (end - start) <<" ms to finish\n\n";

	//Bootstrapping key generation
	std::cout << "Generating bootstrapping key, will take time...\n";
	std::cout << "Get a coffee in the meantime...\n";
	start = currentDateTime();
	auto bootKey = ISLWEOps::BootstrappingKeyGen<Element>(*kp.secretkey, *kpRGSW.publicKey);
	end = currentDateTime();
	std::cout << "Finished bootstrapping key gen\n";
	std::cout << "Bootstrapping Key Generation took "<< (end - start) <<" ms to finish\n\n";

	start = currentDateTime();

	//Get b encoded in grid format and in COEFF representation
	auto bootEncoding = std::move(GetGridEncoding<Element>(cryptoParamRGSW, b, q, gridSize));
	auto bootCipher = RGSWOps<Element>::GridCipherGSWClearEncrypt(cryptoParamRGSW, bootEncoding);
	RGSWOps<Element>::ClearRingMultiplyInPlace(unity, bootCipher);

	for (usint j = 0; j < gridSize; j++) {
		auto ptxt = RGSWOps<Element>::Decrypt(bootCipher[j], kpRGSW.secretKey);
		cout << "bootcipher at " << j << "-th index \n" << ptxt << "\n";
	}

	for (usint i = 0; i < dim; i++) {

		auto ai = a[i];
		auto minus_ai = q.ModSub(ai, q); //ai = -a[i]

		auto aiEncoding = std::move(GetGridEncoding<Element>(cryptoParamRGSW, ai, q, gridSize));
		auto minus_aiEncoding = std::move(GetGridEncoding<Element>(cryptoParamRGSW, minus_ai, q, gridSize));
		//GridCipherTypeGSW<Element> gridCarryOvers;
		for (usint j = 0; j < gridSize; j++) {
			aiEncoding[j][0] += neg;
			minus_aiEncoding[j][0] += neg;
			aiEncoding[j].SwitchFormat();
			minus_aiEncoding[j].SwitchFormat();
			auto first = RGSWOps<Element>::ClearRingMultiply(aiEncoding[j],	bootKey[i][0]); //first is gsw
			auto second = RGSWOps<Element>::ClearRingMultiply(minus_aiEncoding[j], bootKey[i][1]); //second is gsw
			RGSWOps<Element>::AddOneInPlace(first);
			RGSWOps<Element>::AddOneInPlace(second);
			bootCipher[j] = RGSWOps<Element>::Multiply( bootCipher[j], first);
			bootCipher[j] = RGSWOps<Element>::Multiply(bootCipher[j], second);
			//extract sign
			auto signCipher = RGSWOps<Element>::ExtractMaskedCipherAltAlt(bootCipher[j]); //signCipher is gsw
			{
				cout << "printing signCipher after round " << i << "\n\n";
				auto ptxt = RGSWOps<Element>::Decrypt(signCipher, kpRGSW.secretKey);
				cout << ptxt << "\n";
			}

			bootCipher[j] = RGSWOps<Element>::Multiply(bootCipher[j], signCipher); //abs value operation
			/*if (j != gridSize - 1) {
				auto carryOver = RGSWOps<Element>::ExtractCarryOver(signCipher); //carryOver is gsw
				gridCarryOvers.push_back(carryOver);
			}*/
		}
		//add the carry overs
		/*for (usint j = 1; j < gridSize; j++) {
			RGSWOps<Element>::MultiplyInPlace(gridCarryOvers[j-1], bootCipher[j]);
		}

		for (usint j = 0; j < gridSize; j++) {
			auto ptxt = RGSWOps<Element>::Decrypt(bootCipher[j], kpRGSW.secretKey);
			cout << "bootcipher at " << j << "-th index \n" << ptxt << "\n";
		}*/
		cout << "printing after round " << i << "\n\n";
		for (usint j = 0; j < gridSize; j++) {
			auto ptxt = RGSWOps<Element>::Decrypt(bootCipher[j], kpRGSW.secretKey);
			cout << "bootcipher at " << j << "-th index \n" << ptxt << "\n";
		}

	}

	end = currentDateTime();
	std::cout << "Gridstrapping GSW Ciphertext Loop took "<< (end - start) <<" ms to finish\n\n";
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

//This encoding only uses positive encoding and different from FHEW encoding which uses binary coeff
template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	usint N = elemParams->GetRingDimension(); //ring dimension
	Element result(elemParams, COEFFICIENT, true);

	usint idx = (N/q)*message; //idx is between 0 to N-1

	if(idx>N-1){
		cout << q << "\t" << message << "\t" << N << "\t" << idx << '\n';
		throw std::runtime_error("idx exceeds ring dimension");
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

template <class Element>
std::vector<Element> GetGridEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams, const NativeInteger &b, const NativeInteger &q, usint gridDim){
	std::vector<Element> result;
	auto ep = cryptoParams->GetElementParams();
	usint digitSize = q.GetMSB()/gridDim;
	uint64_t base = (uint64_t)1 << digitSize ; //base is modulus of each grid
	uint64_t num = b.ConvertToInt();
	uint64_t mask = 1;
	mask <<= digitSize;
	mask -= 1;

	/*cout << "Inside GetGridEncoding \n";
	cout << q << "\t" << digitSize << "\t" << base << "\t" << num << "\t" << mask << '\n';*/

	for(usint i=0; i< gridDim; i++){
		usint digit = num & mask;
		//cout << digit << '\n';
		num >>= digitSize;
		auto encoding = std::move(GetEncoding<Element>(cryptoParams, digit, base ) );
		result.push_back(std::move(encoding));
	}

	return std::move(result);
}

