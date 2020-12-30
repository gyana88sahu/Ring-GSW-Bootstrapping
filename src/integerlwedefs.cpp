#ifndef LBCRYPTO_INTEGERLWE_C
#define LBCRYPTO_INTEGERLWE_C

#include "integerlwedefs.h"

namespace lbcrypto {

ILWE::ILWE(usint length, NativeInteger modulus) {
	m_a = NativeVector(length, modulus);
}

ILWE::ILWE(const NativeVector& a, const NativeInteger &b){
	m_a = a;
	m_b = b;
}

const NativeVector& ILWE::GetA() const{
	return this->m_a;
}

void ILWE::SetA(const NativeVector &a){
	m_a = a;
}

void ILWE::SetA(NativeVector &&a){
	m_a = std::move(a);
}


const NativeInteger& ILWE::GetB() const{
	return m_b;
}

void ILWE::SetB(const NativeInteger& b){
	m_b = b;
}

ILWEParams::ILWEParams(const NativeInteger p,const NativeInteger mod,usint dim){
	pMod = p;
	modulus = mod;
	m_dim = dim;
}

NativeInteger ILWEParams::GetPlaintextModulus() const{
	return pMod;
}

NativeInteger ILWEParams::GetModulus() const{
	return modulus;
}
usint ILWEParams::GetDimension() const{
	return m_dim;
}

const NativePoly::DugType& ILWEParams::GetDiscreteUniformGenerator() const{
	return *m_dug;
}

const NativePoly::DggType& ILWEParams::GetDiscreteGaussianGenerator() const{
	return *m_dgg;
}

const NativePoly::TugType& ILWEParams::GetTernaryUniformGenerator() const{
	return *m_tug;
}

const NativePoly::BugType& ILWEParams::GetBinaryUniformGenerator() const{
	return *m_bug;
}

void ILWEParams::SetDiscreteUniformGenerator(shared_ptr<NativePoly::DugType> dug){
	m_dug = dug;
}

void ILWEParams::SetDiscreteGaussianGenerator(shared_ptr<NativePoly::DggType> dgg){
	m_dgg = dgg;
}

void ILWEParams::SetTernaryUniformGenerator(shared_ptr<NativePoly::TugType> tug){
	m_tug = tug;
}

void ILWEParams::SetBinaryUniformGenerator(shared_ptr<NativePoly::BugType> bug){
	m_bug = bug;
}

ILWEKey::ILWEKey(const std::shared_ptr<ILWEParams> params){
	m_params = params;
}

const std::shared_ptr<ILWEParams> ILWEKey::GetLWEParams() const{
	return m_params;
}

ILWECiphertext::ILWECiphertext(const shared_ptr<ILWEParams> params):ILWEKey(params){
	m_element = make_shared<ILWE>(params->GetDimension(),params->GetModulus());
}

ILWECiphertext::ILWECiphertext(const ILWECiphertext &rhs):ILWEKey(rhs.GetLWEParams()){
	auto params = rhs.GetLWEParams();
	m_element = make_shared<ILWE>(params->GetDimension(),params->GetModulus());
}

const NativeVector& ILWECiphertext::GetA() const{
	return m_element->GetA();
}

void ILWECiphertext::SetA(const NativeVector& a){
	m_element->SetA(a);
}

const NativeInteger& ILWECiphertext::GetB() const{
	return m_element->GetB();
}


void ILWECiphertext::SetB(const NativeInteger &b){
	m_element->SetB(b);
}

usint ILWECiphertext::GetSizeInBytes(){
	usint sizeResult =0;

	sizeResult+= sizeof(NativeInteger)*(m_element->GetA().GetLength() +1);

	return sizeResult;
}

ILWESecretKey::ILWESecretKey(const shared_ptr<ILWEParams> params):ILWEKey(params){}

void ILWESecretKey::SetSKElement(const NativeVector &s){
	m_sk = s;
}

const NativeVector& ILWESecretKey::GetSKElement() const{
	return m_sk;
}

ILWEPublicKey::ILWEPublicKey(const shared_ptr<ILWEParams> params):ILWEKey(params){
	m_element = make_shared<ILWE>(params->GetDimension(),params->GetModulus());
};

shared_ptr<ILWE> ILWEPublicKey::GetPKElement() const{
	return m_element;
}

void ILWEPublicKey::SetA(const NativeVector &a){
	m_element->SetA(a);

}
void ILWEPublicKey::SetA(NativeVector &&a){
	m_element->SetA(std::move(a));
}

void ILWEPublicKey::SetB(const NativeInteger &b){
	m_element->SetB(b);
}

ILWEKeyPair::ILWEKeyPair(const shared_ptr<ILWEParams> &params){
	secretkey = make_shared<ILWESecretKey>(params);
	publickey = make_shared<ILWEPublicKey>(params);
}


}//namespace ends

#endif
