#ifndef LBCRYPTO_CRYPTO_RGSW_IMPL_H
#define LBCRYPTO_CRYPTO_RGSW_IMPL_H

#include "palisade.h"
#include "RingGSWOPS.cpp"

namespace lbcrypto {

template class RGSWOps<Poly>;

template class RGSWOps<NativePoly>;

}



#endif /* SRC_GSW_IMPL_H_ */
