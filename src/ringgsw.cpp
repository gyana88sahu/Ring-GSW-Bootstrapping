#ifndef LBCRYPTO_CRYPTO_RGSW_C
#define LBCRYPTO_CRYPTO_RGSW_C

#include "ringgsw.h"

namespace lbcrypto {


template <class Element>
LWEForm<Element>::LWEForm(const Element& a, const Element &b){
	this->a = a;
	this->b = b;
}

template <class Element>
LWEForm<Element>::LWEForm(Element &&a, Element &&b){
	this->a = std::move(a);
	this->b = std::move(b);
}

template <class Element>
LWEForm<Element>::LWEForm(const shared_ptr<LPCryptoParameters<Element>> params) {
	const auto paramsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(params);
	a = Element(paramsBGV->GetElementParams(), EVALUATION, true);
	b = Element(paramsBGV->GetElementParams(), EVALUATION, true);
}

template <class Element>
const Element& LWEForm<Element>::GetA() const{
	return this->a;
}

template <class Element>
Element& LWEForm<Element>::GetA() {
	return this->a;
}

template <class Element>
void LWEForm<Element>::SetA(const Element& a){
	this->a = a;
}

template <class Element>
void LWEForm<Element>::SetA(Element &&a){
	this->a = std::move(a);
}

template <class Element>
const Element& LWEForm<Element>::GetB() const{
	return this->b;
}

template <class Element>
Element& LWEForm<Element>::GetB(){
	return this->b;
}

template <class Element>
void LWEForm<Element>::SetB(const Element& b){
	this->b = b;
}

template <class Element>
void LWEForm<Element>::SetB(Element &&b){
	this->b = std::move(b);
}

template <class Element>
void LWEForm<Element>::SwitchFormat(){
	this->a.SwitchFormat();
	this->b.SwitchFormat();
}

template <class Element>
void LWEForm<Element>::ModReduce(const typename Element::Integer &p){
	this->a.ModReduce(p);
	this->b.ModReduce(p);
}

template <class Element>
void LWEForm<Element>::NegateSelf(){
	this->a = this->a.Negate();
	this->b = this->b.Negate();
}

template <class Element>
void LWEForm<Element>::SetAForTowerIdx(const NativePoly &a, usint t){
	throw std::runtime_error("implementation not availble for this element type");
}

template <class Element>
void LWEForm<Element>::SetBForTowerIdx(const NativePoly &b, usint t){
	throw std::runtime_error("implementation not availble for this element type");
}

template <class Element>
void LWEForm<Element>::SetAForTowerIdx(NativePoly &&a, usint t){
	throw std::runtime_error("implementation not availble for this element type");
}

template <class Element>
void LWEForm<Element>::SetBForTowerIdx(NativePoly &&b, usint t){
	throw std::runtime_error("implementation not availble for this element type");
}

template <class Element>
RGSWKey<Element>::RGSWKey(const std::shared_ptr<LPCryptoParameters<Element>> params){
	this->cryptoParams = params;
}

template <class Element>
const std::shared_ptr<LPCryptoParameters<Element>> RGSWKey<Element>::GetCryptoParameters() const{
	return this->cryptoParams;
}

template <class Element>
RGSWCiphertext<Element>::RGSWCiphertext(const shared_ptr<LPCryptoParameters<Element>> params): RGSWKey<Element>(params){

}

template <class Element>
const std::vector<LWEForm<Element>>& RGSWCiphertext<Element>::GetElements() const{
	return this->m_element;
}

template <class Element>
const LWEForm<Element>& RGSWCiphertext<Element>::operator[](usint idx) const {
	return this->m_element[idx];
}

template <class Element>
LWEForm<Element>& RGSWCiphertext<Element>::operator[](usint idx) {
	return this->m_element[idx];
}


template <class Element>
std::vector<LWEForm<Element>>& RGSWCiphertext<Element>::GetElements(){
	return this->m_element;
}

template <class Element>
void RGSWCiphertext<Element>::SwitchFormat(){
	for(usint i=0;i<m_element.size();i++){
		m_element.at(i).SwitchFormat();
	}
}

template <class Element>
void RGSWCiphertext<Element>::ModReduce(){
	const auto &p = this->GetCryptoParameters()->GetPlaintextModulus();
	for (usint i = 0; i < m_element.size(); i++) {
		m_element.at(i).ModReduce(p);
	}
}

template <class Element>
void RGSWCiphertext<Element>::NegateSelf(){
	for (usint i = 0; i < m_element.size(); i++) {
		m_element.at(i).NegateSelf();
	}
}

template <class Element>
void RGSWCiphertext<Element>::SetElementAtIndexForTower(usint rowIdx, usint t, const NativePoly &valueB, const NativePoly &valueA){
	throw std::runtime_error("not implemented");
}

template <class Element>
void RGSWCiphertext<Element>::SetElementAtIndexForTower(usint rowIdx, usint t, NativePoly &&valueB, NativePoly &&valueA){
	throw std::runtime_error("not implemented");
}

template <class Element>
void RGSWCiphertext<Element>::SetElementAtIndex(usint idx, const Element &valueB, const Element& valueA){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm<Element>(valueA,valueB)));
	}
	else{
		m_element.at(idx).SetA(valueA);
		m_element.at(idx).SetB(valueB);
	}
}

template <class Element>
void RGSWCiphertext<Element>::SetElementAtIndex(usint idx, Element &&valueB, Element &&valueA){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm<Element>(std::move(valueA),std::move(valueB))));
	}
	else{
		m_element.at(idx).SetA(std::move(valueA));
		m_element.at(idx).SetB(std::move(valueB));
	}
}

template <class Element>
usint RGSWCiphertext<Element>::GetSizeInBytes(){
	usint size = 0;
	size = m_element.size()*2*sizeof(typename Element::Integer)*m_element[0].GetA().GetRingDimension();
	return size;
}

template <class Element>
RGSWPublicKey<Element>::RGSWPublicKey(const shared_ptr<LPCryptoParameters<Element>> params): RGSWKey<Element>(params){
	m_elements = std::make_shared < LWEForm<Element> > (params);
}

template <class Element>
const LWEForm<Element>& RGSWPublicKey<Element>::GetPublicElements() const {
	return *m_elements;
}

template <class Element>
void RGSWPublicKey<Element>::SetPublicElements(const Element &a, const Element &b) {
	m_elements->SetA(a);
	m_elements->SetB(b);
}

template <class Element>
void RGSWPublicKey<Element>::SetPublicElements(Element &&a, Element &&b) {
	m_elements->SetA(std::move(a));
	m_elements->SetB(std::move(b));
}

template <class Element>
RGSWSecretKey<Element>::RGSWSecretKey(const shared_ptr<LPCryptoParameters<Element>> params): RGSWKey<Element>(params){
	const auto paramsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(params);
	m_sk = std::make_shared <Element> (paramsBGV->GetElementParams(), COEFFICIENT, true);
}

template <class Element>
const Element& RGSWSecretKey<Element>::GetSecretKey(){
	return *this->m_sk;
}

template <class Element>
void RGSWSecretKey<Element>::SetSecretKey(const Element& value){
	*this->m_sk = value;
}

template <class Element>
void RGSWSecretKey<Element>::SetSecretKey(Element &&value){
	*this->m_sk = std::move(value);
}

template <class Element>
RGSWKeySwitchMatrix<Element>::RGSWKeySwitchMatrix(const shared_ptr<LPCryptoParameters<Element>> params): RGSWKey<Element>(params){

}

template <class Element>
const RGSWCiphertext<Element>& RGSWKeySwitchMatrix<Element>::GetKeyMatrixAtIndex(usint idx){
	return m_key.at(idx);
}

template <class Element>
void RGSWKeySwitchMatrix<Element>::SetKeyMatrixAtIndex(usint idx, const RGSWCiphertext<Element> &key){

	auto it = m_key.begin() + idx;
	if(it==m_key.end()){
		m_key.push_back(key);
	}
	else{
		m_key.insert(it,key);
	}
}

template <class Element>
void RGSWKeySwitchMatrix<Element>::SetKeyMatrixAtIndex(usint idx, RGSWCiphertext<Element> &&key){
	auto it = m_key.begin() + idx;
	if(it==m_key.end()){
		m_key.push_back(std::move(key));
	}
	else{
		m_key.insert(it, std::move(key));
	}
}

template <class Element>
RGSWKeyPair<Element>::RGSWKeyPair(const shared_ptr<LPCryptoParameters<Element>> params){
	this->publicKey = std::make_shared<RGSWPublicKey<Element>>(params);
	this->secretKey = std::make_shared<RGSWSecretKey<Element>>(params);
}

}

#endif


