package ce.iohk.bbs.demo

import ce.iohk.bbs.demo.CredentialDocument.{CredentialSubject, IdKeyWord, LinkSecretProof, TypeKeyWord}
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.ld.signature.primitive.MessageDigest
import com.apicatalog.rdf.{Rdf, RdfNQuad}
import io.ipfs.multibase.Base58
import jakarta.json.{Json, JsonObject, JsonObjectBuilder, JsonStructure}
import move.Urdna2015

import scala.jdk.CollectionConverters._

object CredentialDocument {
  val CredentialSubject = "credentialSubject"
  val TypeKeyWord = "type"
  val IdKeyWord = "id"
  val ProofKeyWord = "proofValue"
  val LinkSecretProof = "identifier"
  val PresentationProofKeyWord = "BbsBlsSignature2020"

}

case class CredentialDocument(documentName: String) {


  private val is = getClass.getResourceAsStream(documentName)
  private val doc = JsonDocument.of(is)
  private val jsonDoc = doc.getJsonContent.get()


  def apply(detailsToIssue: IssueDetails): IssuableCredential = {
    val builderForIssuer = Json.createObjectBuilder (jsonDoc.asJsonObject () )
    detailsToIssue.issuerDetails.foreach {
      case (k, v) => builderForIssuer.add(k,v)
    }
    val builderForCredential =
      Json.createObjectBuilder(
        jsonDoc.asJsonObject().getJsonObject(CredentialSubject)
      )

    detailsToIssue.credentialDetails.foreach {
      case (k, v) => builderForCredential.add(k, v)
    }

    val result = builderForIssuer.add(CredentialSubject, builderForCredential).build()
    println(result.asJsonObject().toString)
    IssuableCredential(
      result,
      detailsToIssue.credentialDetails(IdKeyWord)
    )
  }
}


case class IssueDetails(issuerDetails: Map[String, String], credentialDetails: Map[String, String])

case class IssuableCredential(issuableJson: JsonObject, subject: String) {
  lazy val parsed = VCDocumentParser.parse(issuableJson, subject)
  lazy val digests: Seq[Array[Byte]] = {
    Seq(parsed.headerDigest) ++ parsed.digests
  }

  lazy val numParts: Int = parsed.numParts + 1

  def filterNotClaims(forPresentation: Seq[String], linkSecret: Array[Byte]): JsonObject = {
    val builder = Json.createObjectBuilder(issuableJson)
    val attrs = issuableJson.getJsonObject(CredentialSubject)

    val builderForCredential =
      Json.createObjectBuilder(
        attrs
      )

    attrs.keySet().forEach(attr => {
      if (attr == TypeKeyWord) {
      } else if (attr == IdKeyWord) {
      } else builderForCredential.remove(attr)
    })

    val linkAsString = Base58.encode(linkSecret)
    builderForCredential.add(LinkSecretProof, Json.createValue(linkAsString))
    linkSecret
    attrs.keySet().forEach(attr =>{
      if(forPresentation.contains(attr)) {
        builderForCredential.add(attr, attrs.getJsonString(attr))
      }
    })

    builder.add(CredentialSubject, builderForCredential).build()
  }
}


