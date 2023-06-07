package ce.iohk.bbs.demo

import ce.iohk.bbs.BbsPlusOps.BlindCommitment
import ce.iohk.bbs.demo.CredentialDocument.{PresentationProofKeyWord, ProofKeyWord}
import ce.iohk.bbs.demo.Holder.Presentation
import ce.iohk.bbs.demo.Issuer.IssuedCred
import ce.iohk.bbs.jpi.BbsJpi
import ce.iohk.bbs.{MessageWithProofType, ProofMessageType}
import com.apicatalog.ld.signature.proof.Proof
import io.ipfs.multibase.Base58
import jakarta.json.{Json, JsonObject}

import scala.jdk.CollectionConverters._
import scala.util.Random

object Holder {
  case class Presentation(
                          jsonObject: JsonObject,
                          subject: String,
                          /*proof: Array[Byte],
                          messagesWithProofType: Seq[MessageWithProofType]*/)
}
class Holder(bbsJpi: BbsJpi, linkSecret: LinkSecret, publicKey: Array[Byte]) {

  val nonce = Random.nextBytes(60)

  val linkSecretBytes = linkSecret.proofOfKnowledge(nonce)

  def createLinkSecretCommitment(numMessages:Int): BlindCommitment = {
    //create link secret
    val pKey = bbsJpi.createBbsPublicKey(publicKey, numMessages)

    bbsJpi.createLinkSecretCommitment(pKey, nonce, linkSecretBytes)
  }

  def presentation(issuedCred: IssuedCred,
                   challenge: VerifierChallenge, blindingFactor: Array[Byte]): Presentation = {
    //for presentation
    val revealIndices = Seq(0) ++ issuedCred.findIndices(challenge.claimNames, 1)

    //TODO use nonce from challenge
    require(revealIndices.nonEmpty, "Must reveal something?")

    val msgsWithProofType =
      MessageWithProofType(
        linkSecretBytes,
        ProofMessageType.Revealed) +: issuedCred.digests.zipWithIndex.map {
      case (m, i) => MessageWithProofType(m, revealOrHide(i, revealIndices))
    }
    val pKey = bbsJpi.createBbsPublicKey(publicKey, issuedCred.issuable.numParts)

    val proofForPresentation = bbsJpi.createProof(
      issuedCred.signature,
      nonce,
      pKey,
      blindingFactor,
      msgsWithProofType.asJava
    )

    val jsonObj = issuedCred.issuable.filterNotClaims(challenge.claimNames, linkSecretBytes)
    val builder = Json.createObjectBuilder(jsonObj)
    val proofJson = Json.createObjectBuilder()
    val proofAsString = Base58.encode(proofForPresentation)
    println(s"IN $proofAsString")
    proofJson.add(ProofKeyWord, Json.createValue(proofAsString))
    val resultJson = builder.add(PresentationProofKeyWord, proofJson).build()



    println(resultJson)
    Presentation(resultJson, issuedCred.issuable.subject)
  }


  def revealOrHide(index: Int, revealIndices: Seq[Int]): ProofMessageType = {
    if (revealIndices.contains(index)) ProofMessageType.Revealed
    else ProofMessageType.HiddenProofSpecificBlinding
  }

}
