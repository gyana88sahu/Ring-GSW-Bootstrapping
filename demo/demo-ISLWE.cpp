#include "../src/ISLWE.cpp"
#include "../src/integerlwedefs.h"

using namespace lbcrypto;
using namespace std;

void runEncryptDecrypt(usint m);
void runModReduce();
void runModReduceSLWE(usint m);

int main(int argc, char *argv[]){

	//usint m = 4;
	//runEncryptDecrypt(m);
	//runModReduce();
	runModReduceSLWE(2);
	return 0;
}

void runEncryptDecrypt(usint m){
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 500;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	//cout<<dgg->GenerateVector(dim,q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ISLWEOps::KeyGen(params);

	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);

	usint message = ISLWEOps::Decrypt(cipher, *kp.secretkey);

	cout << message << "\t";
}

void runModReduceSLWE(usint m){
	NativeInteger q(937);
	NativeInteger qDash(512);
	NativeInteger p(5);
	usint dim = 500;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	//cout<<dgg->GenerateVector(dim,q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ISLWEOps::KeyGen(params);

	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);

	usint message = ISLWEOps::Decrypt(cipher, *kp.secretkey);
	cout << message << "\n";

	auto dggDash = make_shared<NativePoly::DggType>(2.0);
	auto dugDash = make_shared<NativePoly::DugType>();
	dugDash->SetModulus(qDash);
	shared_ptr<ILWEParams> paramDash = make_shared<ILWEParams>(p,qDash,dim);

	paramDash->SetDiscreteUniformGenerator(dugDash);
	paramDash->SetDiscreteGaussianGenerator(dggDash);


	ILWEKeyPair kpNew(paramDash);
	auto sDash = kp.secretkey->GetSKElement();
	sDash.SwitchModulus(qDash);
	kpNew.secretkey->SetSKElement(sDash);


	auto cipherDash = ISLWEOps::ModSwitch(cipher,qDash);


	message = ISLWEOps::Decrypt(cipherDash, *kpNew.secretkey);
	cout << message << "\n";

}


void runModReduce(){

	NativeInteger q(937);
	NativeInteger qDash(512);
	NativeInteger p(5);
	usint dim = 100;
	NativeInteger m(2);

	auto dgg1 = make_shared<NativePoly::DggType>(2.0);
	auto dgg2 = make_shared<NativePoly::DggType>(2.0);
	auto dug1 = make_shared<NativePoly::DugType>();
	auto dug2 = make_shared<NativePoly::DugType>();

	dug1->SetModulus(q);
	dug2->SetModulus(qDash);

	//cout<<dgg->GenerateVector(dim,q);

	shared_ptr<ILWEParams> params1 = make_shared < ILWEParams > (p, q, dim);
	shared_ptr<ILWEParams> params2 = make_shared < ILWEParams > (p, qDash, dim);

	params1->SetDiscreteUniformGenerator(dug1);
	params1->SetDiscreteGaussianGenerator(dgg1);

	params2->SetDiscreteUniformGenerator(dug2);
	params2->SetDiscreteGaussianGenerator(dgg2);

	auto a = dug1->GenerateVector(dim);
	auto s = dgg1->GenerateVector(dim, q);
	auto e = dgg1->GenerateInteger(q);
	std::cout << "error is\t"<<e<<'\n';

	auto b = Sum1(a*s) + e*p + m;

	auto mVerify = b.ModSub(Sum1(a*s),q);
	std::cout << mVerify << '\n';

	mVerify = mVerify.Mod(p);
	std::cout << mVerify << '\n';

	NativeVector aDash(dim,qDash);
	NativeInteger bDash;

	//cout << "printitng a\n"<< a<<'\n';

	for (usint i = 0; i < dim; i++) {
		auto num = a[i];
		num = num*qDash;
		num = num/q;

		auto diff = (a[i].Mod(p)).ModSub(num.Mod(p),p);

		aDash[i] = num + diff;
	}

	NativeInteger num = b;
	num = num*qDash;
	num = num/q;
	auto diff = (b.Mod(p)).ModSub(num.Mod(p),p);
	bDash = num + diff;

	//cout << "printitng aDash \n"<< aDash<<'\n';
	auto sDash = s;
	sDash.SwitchModulus(qDash);

	cout << "printing sDash"<< sDash<<'\n';

	mVerify = bDash.ModSub(Sum1(aDash*sDash),qDash);
	std::cout << mVerify << '\n';
	std::cout << mVerify.Mod(p) << '\n';

}
