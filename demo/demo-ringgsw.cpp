
//#include "../src/RingGSWOPS.h"
#include "../src/gsw-impl.cpp"

using namespace std;
using namespace lbcrypto;

void runEncryptDecrypt();
void runHomMultiply();
void runEncryptDecryptNI();

int main(int argc, char *argv[]) {

	//runEncryptDecrypt();
	//runHomMultiply();
	runEncryptDecryptNI();
	return 0;
}

void runEncryptDecrypt(){
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

	RGSWKeyPair<Poly> kp = RGSWOps<Poly>::KeyGen(params);

	Poly message(ep, COEFFICIENT);

	message = {0,1,0,0};

	auto cipher = RGSWOps<Poly>::Encrypt(*kp.publicKey, message);


	auto decryptResult = RGSWOps<Poly>::Decrypt(cipher, kp.secretKey);

	std::cout << decryptResult << '\n';
}

void runHomMultiply(){
	float stdDev = 4;
	usint relinWindow = 8;

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

	RGSWKeyPair<Poly> kp = RGSWOps<Poly>::KeyGen(params);

	Poly message1(ep, COEFFICIENT);
	Poly message2(ep, COEFFICIENT);

	message1 = {0,1,0,0};
	message2 = {0,0,0,1};

	auto cipher1 = RGSWOps<Poly>::Encrypt(*kp.publicKey, message1);
	auto cipher2 = RGSWOps<Poly>::Encrypt(*kp.publicKey, message2);

	auto cipherMult = RGSWOps<Poly>::Multiply(cipher1,cipher2);

	auto decryptResult = RGSWOps<Poly>::Decrypt(cipherMult, kp.secretKey);

	std::cout << decryptResult << '\n';
}

void runEncryptDecryptNI(){

	float stdDev = 4;
	usint relinWindow = 4;

	usint m = 8;
	NativeInteger modulus("2199023288321");
	usint plaintextmodulus(5);
	NativeInteger rootOfUnity;

	modulus = NextPrime(modulus, m);
	rootOfUnity = RootOfUnity(m, modulus);

	cout << modulus << '\n';
	cout << rootOfUnity << '\n';

	auto ep = make_shared < ILNativeParams > (m, modulus, rootOfUnity);

	auto params = make_shared<LPCryptoParametersBGV<NativePoly>> (ep, plaintextmodulus, stdDev, 9, 1.006, relinWindow, RLWE, 1);

	RGSWKeyPair<NativePoly> kp = RGSWOps<NativePoly>::KeyGen(params);

	NativePoly message(ep, COEFFICIENT);

	message = {0,1,0,0};

	auto cipher = RGSWOps<NativePoly>::Encrypt(*kp.publicKey, message);


	auto decryptResult = RGSWOps<NativePoly>::Decrypt(cipher, kp.secretKey);

	std::cout << decryptResult << '\n';
}


