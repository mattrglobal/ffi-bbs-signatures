package ce.iohk.bbs.demo

import ce.iohk.bbs.demo.CredentialDocument.{CredentialSubject, IdKeyWord, LinkSecretProof, PresentationProofKeyWord}
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.ld.signature.primitive.MessageDigest
import com.apicatalog.rdf.{Rdf, RdfNQuad}
import io.ipfs.multibase.Base58
import jakarta.json.{Json, JsonObject, JsonStructure}
import move.Urdna2015

import scala.jdk.CollectionConverters._

object VCDocumentParser {

  private val md = new MessageDigest("SHA-256")

  def filterIndices[A](seq: Seq[A], requiredIndices: Seq[Int]): Seq[A] = {
    seq.zipWithIndex.filter {
      case (e, i) => requiredIndices.contains(i)
    }.map(_._1)
  }

  def findIndices(
                   labels: Seq[String],
                   rdfNQuad: Seq[RdfNQuad],
                   offset: Int = 0): Seq[Int] = {

    def isLabel(s: String): Boolean = labels.exists(l => s.endsWith(l))

    rdfNQuad.zipWithIndex.filter {
      q_i => isLabel(q_i._1.getPredicate.getValue)
    } map (_._2 + offset)
  }


  def parse(jsonStructure: JsonStructure, subject: String): Parsed = {

    val jsonMinusProof = Json.createObjectBuilder(
      jsonStructure.asJsonObject())
      .remove(PresentationProofKeyWord)

    val jsonMinusProofMinusLink = Json.createObjectBuilder(
      jsonStructure.asJsonObject().getJsonObject(CredentialSubject))
      .remove(LinkSecretProof)

    val j = jsonMinusProof.addAll(jsonMinusProofMinusLink).build()
    val parser = new Urdna2015(j)
    val normData = parser.toNormalRdf

    val (attributesQuads, header) = normData.toList.asScala.toSeq.partition { ds =>
      ds.getSubject.getValue == subject
    }

    val headerDataSet = {
      val ds = Rdf.createDataset()
      header.map { rdfNQuad =>
        ds.add(rdfNQuad)
      }
      ds
    }

    val credentialDataSets = attributesQuads.map(rdfNQuad => {
      val ds = Rdf.createDataset()
      ds.add(rdfNQuad)
      ds
    })


    val credentialDataSetsDigests: Seq[Array[Byte]] = credentialDataSets.map(ds => {
      val canonical = parser.canonicalize(ds)
      val digest = md.digest(canonical)
      println(s"${ds.toList.asScala.head} ${Base58.encode(digest)}")
      digest
    })

    val headerDataSetDigest = {
      val canon = parser.canonicalize(headerDataSet)
      md.digest(canon)
    }

    val numParts: Int = 1 /*header*/ + credentialDataSetsDigests.length

    val digests = credentialDataSetsDigests
    Parsed(numParts, jsonStructure, digests, headerDataSetDigest, attributesQuads)
  }

  def rdfQuadToDigest(rdfNQuad: RdfNQuad, json: JsonObject ): Array[Byte] = {
    val ds = Rdf.createDataset()
    ds.add(rdfNQuad)
    val parser = new Urdna2015(json)

    val canon = parser.canonicalize(ds)
    md.digest(canon)
  }

}

case class VCDocumentParser(documentName: String, subject: String) {

  private val is = getClass.getResourceAsStream(documentName)
  private val doc = JsonDocument.of(is)
  private val jsonDoc = doc.getJsonContent.get()


  val parsed: Parsed = VCDocumentParser.parse(jsonDoc, subject)

  def update(updates: Map[String, String]): Parsed = {

    val builder = Json.createObjectBuilder(jsonDoc.asJsonObject())
    updates.foreach { case (k, v) => builder.add(k, v) }
    VCDocumentParser.parse(builder.build(), subject)
  }
}

case class Rdfs(json: JsonObject,
                digests: Seq[Array[Byte]],
                quads: Seq[RdfNQuad]) {
  def numMessages: Int = quads.size

  def findIndices(
                   labels: Seq[String],
                   offset: Int = 0): Seq[Int] = {
    VCDocumentParser.findIndices(labels, quads, offset)
  }

  def filterIndices(revealIndices: Seq[Int]): Seq[Array[Byte]] = {
    VCDocumentParser.filterIndices(digests, revealIndices)
  }

}

case class Parsed(
                   numParts: Int,
                   jsonStructure: JsonStructure,
                   digests: Seq[Array[Byte]],
                   headerDigest: Array[Byte],
                   attributeQuads: Seq[RdfNQuad]) {

  def findIndices(
                   labels: Seq[String],
                   offset: Int = 0): Seq[Int] = {
    VCDocumentParser.findIndices(labels, attributeQuads, offset)
  }

  def find(
                   labels: Seq[String],
                   offset: Int = 0): Seq[Array[Byte]] = {
    val found = VCDocumentParser.findIndices(labels, attributeQuads, offset)
    found.map { f =>
      VCDocumentParser.rdfQuadToDigest(attributeQuads(f), jsonStructure.asJsonObject())
    }
  }

  def filterIndices(revealIndices: Seq[Int]): Seq[Array[Byte]] = {
    VCDocumentParser.filterIndices(digests, revealIndices)
  }
}


//    attributeQuads.map(rdf => {
//      updates.keys.find(k => rdf.getPredicate.getValue.endsWith(k)) match {
//        case Some(value) =>
//
//          val v = rdf.getObject.asLiteral().getValue
//          val dt = rdf.getObject.asLiteral().getDatatype
//          val newValue = updates(value)
//          val newObject = Rdf.createTypedString(newValue, dt)
//
//          Rdf.createNQuad(rdf.getSubject, rdf.getPredicate, newObject, rdf.getGraphName.orElse(null))
//        case None => rdf
//      }
//    })


