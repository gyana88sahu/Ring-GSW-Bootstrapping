#include "../src/ILWEOps.h"
#include "../src/integerlwedefs.h"

using namespace lbcrypto;
using namespace std;

int main(int argc, char *argv[]){

	NativeInteger q(512);
	NativeInteger p(4);
	usint dim = 500;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	//cout<<dgg->GenerateVector(dim,q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ILWEOps::KeyGen(params);

	auto cipher = ILWEOps::Encrypt(*kp.publickey, 3);

	usint message = ILWEOps::Decrypt(cipher, *kp.secretkey);

	cout << message << "\t";

	cout << "Running HomNand Operation\n";

	usint m1 = 0, m2 = 1;

	cout << "operand 1 is: " << m1 << '\n';
	cout << "operand 2 is: " << m2 << '\n';

	auto cipher1 = ILWEOps::Encrypt(*kp.publickey, m1);
	auto cipher2 = ILWEOps::Encrypt(*kp.publickey, m2);

	auto cipherNAND = ILWEOps::EvalNand(cipher1,cipher2);

	auto nand = ILWEOps::Decrypt(cipherNAND,*kp.secretkey);

	cout << "NAND of "<<m1<<' '<<m2<<" is: "<<nand<<'\n';

	return 0;
}




