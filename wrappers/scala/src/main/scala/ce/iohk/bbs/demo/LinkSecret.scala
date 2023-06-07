package ce.iohk.bbs.demo

import ce.iohk.bbs.jpi.{BbsJpi, KeyPair}

object LinkSecret {

  def apply(bbsJpi: BbsJpi): LinkSecret = {
    val pair = bbsJpi.createKeyPair()
    new LinkSecret(bbsJpi, pair)
  }
}
class LinkSecret(bbsJpi: BbsJpi, pair: KeyPair) {

  private val bbsPubKey = bbsJpi.createBbsPublicKey(pair.getPublicKey, 1)
  def proofOfKnowledge(challenge: Array[Byte]): Array[Byte] = {

    bbsJpi.sign(Array(challenge), new KeyPair(pair.getPrivateKey, bbsPubKey))
  }

  def verifier: LinkSecretVerifier = new LinkSecretVerifier(bbsJpi, bbsPubKey)
}
