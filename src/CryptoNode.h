#ifndef CRYPTO_NODE_H
#define CRYPTO_NODE_H

#include "palisade.h"
#include "ringgsw.h"
#include <string>

namespace lbcrypto{

template <class Element>
class CryptoNode{

public:
	CryptoNode(){
		left = nullptr;
		right = nullptr;
		nop = false;
		id = "";
	}

	bool nop;
	string id;
	std::shared_ptr<CryptoNode<Element>> left;
	std::shared_ptr<CryptoNode<Element>> right;
	std::shared_ptr<RGSWCiphertext<Element>> m_cipher;

};


}




#endif
