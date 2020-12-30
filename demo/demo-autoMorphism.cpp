#include "palisade.h"
#include "cryptocontext.h"

#include "encoding/encodings.h"


using namespace lbcrypto;
using namespace std;

int main(int argc, char *argv[]){

	if(argc!=3){
		cout << "Must Enter automorphism index and message index \n";
		return -1;
	}

	usint i = atoi(argv[1]);
	usint mssgIdx = atoi(argv[2]);
	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;
	usint relWindow = 1;
	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(
		params, plaintextModulus,
		relWindow, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext;

	//std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	std::vector<int64_t> vectorOfInts(m/2,0);
	vectorOfInts[mssgIdx] = 1;
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	Ciphertext<Poly> p1;

	p1 = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, p1, &intArrayNew);

	cout << intArrayNew->GetPackedValue();

}
