#ifndef CRYPTO_TREE_CPP
#define CRYPTO_TREE_CPP

#include "CryptoTree.h"
#include "gsw-impl.cpp"

namespace lbcrypto{

template <class Element>
std::shared_ptr<RGSWSecretKey<Element>> CryptoTree<Element>::m_sk = nullptr;

template <class Element>
void CryptoTree<Element>::Multiply(){//Multiplication by post order traversal

	if (root == nullptr) {
		std::cout << "error\n";
	}

	Multiply(root->left);
	Multiply(root->right);

	if (root->left->nop == false && root->right->nop == false) {
		root->m_cipher =
				RGSWOps<Element>::Multiply(root->left->m_cipher,root->right->m_cipher);
		return;
	}

	if (root->left->nop) {
		root->m_cipher = root->right->m_cipher;
	}

	if (root->right->nop) {
		root->m_cipher = root->left->m_cipher;
	}

}

template <class Element>
void CryptoTree<Element>::Insert(std::vector<std::shared_ptr<RGSWCiphertext<Element>>> ciphers){

}

template <class Element>
void CryptoTree<Element>::BuildLevels(usint nNodes){

	usint totalNodes = nNodes % 2 == 0 ? nNodes : nNodes + 1;

	std::vector < std::shared_ptr<CryptoNode<Element>> > bottomLayer;

	for (usint i = 0; i < totalNodes; i++) {
		bottomLayer.push_back(make_shared<CryptoNode<Element>>());
	}

	if (totalNodes != nNodes) {
		bottomLayer.back()->nop = true;
	}
	std::vector < std::shared_ptr<CryptoNode<Element>> > layer;
	usint levels = std::ceil(std::log2(totalNodes));

	for(usint i=0;i<levels;i++){
		for(usint j=0;j<bottomLayer.size();j+=2){
			layer.push_back(make_shared<CryptoNode<Element>>());
			layer.back()->left = bottomLayer[j];
			layer.back()->right = bottomLayer[j+1];
		}
		bottomLayer.clear();
		bottomLayer = layer;
		layer.clear();
	}

	root = bottomLayer.back();
	bottomLayer.clear();
}

template <class Element>
void CryptoTree<Element>::Insert(std::shared_ptr<RGSWCiphertext<Element>> cipher,string id){
	if(root==nullptr)
		return;

	bool inserted = Insert(cipher, root->left,id);
	if (!inserted) {
		Insert(cipher, root->right,id);
	}

}

template <class Element>
void CryptoTree<Element>::Multiply(shared_ptr<CryptoNode<Element>> head){
	if (head == nullptr)
		return;

	if (head->left == nullptr && head->right == nullptr)
		return;

	Multiply(head->left);
	Multiply(head->right);

	if (head->left->nop == false && head->right->nop == false) {
		head->m_cipher = RGSWOps<Element>::Multiply(head->left->m_cipher,
				head->right->m_cipher);
		head->id = head->left->id + " AND " + head->right->id;
		std::cout<< head->id<<'\n';
		std::cout << "Multiplication done\n";
		auto decr = RGSWOps<Element>::Decrypt(head->m_cipher, m_sk);
		std::cout << decr << '\n';
		return;
	}

	if (head->left->nop) {
		head->m_cipher = head->right->m_cipher;
	}

	if (head->right->nop) {
		head->m_cipher = head->left->m_cipher;
	}
}

template <class Element>
bool CryptoTree<Element>::Insert(std::shared_ptr<RGSWCiphertext<Element>> cipher, shared_ptr<CryptoNode<Element>> head,string id){
	if(head==nullptr){
		return false;
	}

	if(head->left==nullptr && head->right==nullptr && head->m_cipher==nullptr){
		if(head->nop){
			throw std::runtime_error("Invalid operation");
		}
		head->m_cipher = cipher;
		head->id = id;
		return true;
	}
	if(head->left==nullptr && head->right==nullptr && head->m_cipher!=nullptr){
		return false;
	}

	bool inserted = Insert(cipher, head->left,id);
	if (!inserted) {
		inserted = Insert(cipher, head->right,id);
	}

	return inserted;
}

template <class Element>
void CryptoTree<Element>::Set(const std::shared_ptr<RGSWSecretKey<Element>> sk){
	m_sk = sk;
}

}
#endif
