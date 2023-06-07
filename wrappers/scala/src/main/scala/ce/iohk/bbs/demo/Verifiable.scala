package ce.iohk.bbs.demo

import ce.iohk.bbs.demo.CredentialDocument.{CredentialSubject, IdKeyWord, LinkSecretProof, PresentationProofKeyWord, ProofKeyWord}
import ce.iohk.bbs.demo.Holder.Presentation
import io.ipfs.multibase.Base58

import scala.jdk.CollectionConverters.{CollectionHasAsScala, MapHasAsScala}


case class Verifiable(presentation: Presentation) {

  val parsed = VCDocumentParser.parse(presentation.jsonObject, presentation.subject)

  // oth message must be link
  // then the header
  //then the claims
  def proof: Array[Byte] = {
    val proofAsString = presentation
      .jsonObject
      .getJsonObject(PresentationProofKeyWord)
      .getString(ProofKeyWord)

    println(s"AS $proofAsString")
    Base58.decode(proofAsString)
  }

  def linkMessage: Array[Byte] = {
    val asString = presentation
      .jsonObject.getJsonObject(CredentialSubject).getString(LinkSecretProof)
    Base58.decode(asString)
  }

  private val ignore: Seq[String] = Seq("id", "type", "identifier")

  private def claims: Seq[String] = {
    val asAry = presentation
      .jsonObject.getJsonObject(CredentialSubject)
    asAry.keySet().asScala.filterNot(e => ignore.contains(e)).toSeq
  }

  def messages: Seq[Array[Byte]] = {
    // the secret link
    // the header digest
    // the revealed

    val revealed = Seq(parsed.headerDigest) ++ parsed.filterIndices(parsed.findIndices(claims))
    Seq(linkMessage) ++ revealed
  }
}
