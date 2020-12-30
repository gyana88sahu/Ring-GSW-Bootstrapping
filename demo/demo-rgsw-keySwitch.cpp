#include "palisade.h"
#include "../src/RingGSWOPS.cpp"

using namespace lbcrypto;
using namespace std;

void runKeySwitchSmallParamteres();

void runKeySwitchFullParamteres();

int main(){

	runKeySwitchSmallParamteres();

	return 0;
}

void runKeySwitchSmallParamteres(){

	float stdDev = 4;
	usint relinWindow = 4;

	usint m = 8;
	BigInteger modulus("2199023288321");
	usint plaintextmodulus(5);
	BigInteger rootOfUnity;

	modulus = NextPrime(modulus, m);
	rootOfUnity = RootOfUnity(m, modulus);

	cout << modulus << '\n';
	cout << rootOfUnity << '\n';

	auto ep = make_shared < ILParams > (m, modulus, rootOfUnity);

	auto params = make_shared<LPCryptoParametersBGV<Poly>> (ep, plaintextmodulus, stdDev, 9, 1.006, relinWindow, RLWE, 1);

	RGSWKeyPair<Poly> kpOld = RGSWOps<Poly>::KeyGen(params);

	RGSWKeyPair<Poly> kpNew = RGSWOps<Poly>::KeyGen(params);


	Poly message(ep, COEFFICIENT);

	message = {0,1,0,0};

	auto cipher = RGSWOps<Poly>::Encrypt(*kpOld.publicKey, message);


	auto decryptResult = RGSWOps<Poly>::Decrypt(cipher, kpOld.secretKey);

	std::cout << decryptResult << '\n';

	auto evalKey = RGSWOps<Poly>::KeySwitchGen(kpOld.secretKey,kpNew.secretKey);

	auto cipherNew = RGSWOps<Poly>::KeySwitch(cipher, evalKey);

	auto decryptResultNew = RGSWOps<Poly>::Decrypt(cipherNew, kpNew.secretKey);

	std::cout << decryptResultNew << '\n';
}

void runKeySwitchFullParamteres() {


}
