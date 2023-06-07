package ce.iohk.bbs.demo

import ce.iohk.bbs.jpi.{BbsJpi, KeyPair}

class LinkSecretVerifier(bbsJpi: BbsJpi, publicKey: Array[Byte]) {

  def verify(challenge: Array[Byte],
             proof: Array[Byte] ): Boolean = {
    bbsJpi.verify(Array(challenge), proof, publicKey)
  }

}
