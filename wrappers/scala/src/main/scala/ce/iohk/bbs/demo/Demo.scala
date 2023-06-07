package ce.iohk.bbs.demo

import buildinfo.BuildInfo
import ce.iohk.bbs.{ClasspathSharedObject, MessageWithProofType, ProofMessageType}
import ce.iohk.bbs.jpi.Bbs

import scala.jdk.CollectionConverters._




object Demo {

  def main(args: Array[String]): Unit = {

    println("DEMO BEGINS")

    val bbsJpi = Bbs.create(
      java.util.List.of(BuildInfo.TargetForBbsSharedObjectDownload, "."),
      (ClasspathSharedObject.namesOfSharedObjectsToLoad).asJava
    )

    val issuersKeyPair = bbsJpi.createKeyPair

    val credDoc = CredentialDocument("/inputDocument.json")
    val subjectDetails: Map[String, String] = Map(
      ("id", "did:didnt:wont"),
      ("givenName", "Alan"),
      ("gender", "Male"),
      ("birthDate", "1988-07-17")
    )
    val credentialDetails = Map(
      ("identifier", "345345345345"),
      ("issuanceDate", "2023-12-03T12:19:52Z"),
      ("expirationDate", "2024-12-03T12:19:52Z")
    )

    val issueDetails = IssueDetails(credentialDetails, subjectDetails)
    val issuable = credDoc(issueDetails)

    val issuer = new Issuer(bbsJpi, issuersKeyPair)

    val linkSecret = LinkSecret(bbsJpi)
    val holder = new Holder(bbsJpi, linkSecret, issuer.publicKey)
    val numMessagesIncCommitment = issuable.numParts
    val commitment = holder.createLinkSecretCommitment(numMessagesIncCommitment)

    val issuedCred = issuer.issue(issuable, commitment.commitment)

    val verifier = new Verifier(bbsJpi, linkSecret.verifier, issuer.publicKey)

    val presentAttrs = Seq("birthDate", "gender")
    val challenge = VerifierChallenge(verifier.newNonce, presentAttrs)

    val presentation = holder
      .presentation(
        issuedCred,
        challenge,
        commitment.blindingFactor
      )

    val verifiable = Verifiable(presentation)

    val isGood = verifier.verify(verifiable.proof,
      verifiable.messages,
      holder.nonce,
      numMessagesIncCommitment
    )


    System.out.println("isGood: (no exceptions) " + isGood )

  }

}
