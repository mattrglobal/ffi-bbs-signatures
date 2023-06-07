package ce.iohk.bbs.demo

import ce.iohk.bbs.jpi.BbsJpi

import java.security.SecureRandom
import scala.jdk.CollectionConverters._

class Verifier(bbsJpi: BbsJpi,
               linkSecretVerifier: LinkSecretVerifier,
               publicKey: Array[Byte]) {

  def verify(proofForPresentation: Array[Byte],
             messagesForPresentation: Seq[Array[Byte]],
             nonce: Array[Byte],
             numMessages: Int): Boolean = {
    val pKey = bbsJpi.createBbsPublicKey(publicKey, numMessages)
    val linkOk = linkSecretVerifier.verify(nonce, messagesForPresentation.head)
    val proofOk = bbsJpi.verifyProof(proofForPresentation, pKey, nonce, messagesForPresentation.asJava)
    linkOk && proofOk
  }

  def newNonce: Array[Byte] = SecureRandom.getSeed(32)
}

case class VerifierChallenge(nonce: Array[Byte], claimNames: Seq[String])