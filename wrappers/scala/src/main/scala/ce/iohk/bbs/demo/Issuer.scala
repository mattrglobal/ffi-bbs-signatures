package ce.iohk.bbs.demo

import ce.iohk.bbs.demo.Issuer.IssuedCred
import ce.iohk.bbs.jpi.{BbsJpi, KeyPair}

import scala.jdk.CollectionConverters._

object Issuer {
  case class IssuedCred(
                         signature: Array[Byte],
                         issuable: IssuableCredential) {
    def findIndices(claimNames: Seq[String], offset:Int): Seq[Int] = {
      VCDocumentParser.findIndices(claimNames, issuable.parsed.attributeQuads, offset)
    }
    def filterIndices(claims: Seq[Int]): Seq[Array[Byte]] = {
      VCDocumentParser.filterIndices(issuable.digests, claims)
    }

    def digests: Seq[Array[Byte]] = issuable.digests
  }
}
class Issuer(
              bbsJpi: BbsJpi,
              keyPair: KeyPair) {

  def publicKey: Array[Byte] = keyPair.getPublicKey

  def issue(issuable: IssuableCredential,
            commitment: Array[Byte]): IssuedCred = {

    val bbsPublicKey = bbsJpi.createBbsPublicKey(publicKey, issuable.numParts)
    val signature = bbsJpi.blindSign(
      bbsPublicKey,
      keyPair.getPrivateKey,
      commitment,
      issuable.digests.asJava,
      1)

    IssuedCred(signature, issuable)
  }


}
