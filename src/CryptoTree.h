#ifndef CRYPTO_TREE_H
#define CRYPTO_TREE_H

#include "palisade.h"
#include "CryptoNode.h"
#include "ringgsw.h"
#include "RingGSWOPS.h"
#include <string>

namespace lbcrypto{

template <class Element>
class CryptoTree{
	static std::shared_ptr<RGSWSecretKey<Element>> m_sk;

public:
	CryptoTree(){
		root = nullptr;
	}

	std::shared_ptr<CryptoNode<Element>> root;

	void Multiply();
	void Insert(std::vector<std::shared_ptr<RGSWCiphertext<Element>>> ciphers);
	void BuildLevels(usint nNodes);
	void Insert(std::shared_ptr<RGSWCiphertext<Element>> cipher,string id);
	static void Set(const std::shared_ptr<RGSWSecretKey<Element>> sk);


	static void Multiply(shared_ptr<CryptoNode<Element>> head);
	static bool Insert(std::shared_ptr<RGSWCiphertext<Element>> cipher, shared_ptr<CryptoNode<Element>> head,string id);
};


}




#endif
