import EndToEnd.printIt
import buildinfo.BuildInfo
import ce.iohk.bbs.BbsPlusOps._
import ce.iohk.bbs.{BbsPlusNative, MessageWithProofType, ProofMessageType}

import scala.util.Random

object Mainer {

  def main(args: Array[String]): Unit = {

    println("Issue a credential that contains a link secret")

    val messageCount = 6
    val messages = ((0 until messageCount) map (_ => Random.nextBytes(50))).toArray

    val bbsApi = BbsPlus(
      BbsPlusNative(
        Seq(BuildInfo.TargetForBbsSharedObjectDownload, ".")
      )
    )

    /*
     * Create presentation that contains a selective disclosure
     */

    val seed: Array[Byte] = Random.nextBytes(128)

    val isOkResult = for {

      //Issuer creates keys
      issuerKeys <- bbsApi.createBlsKeyPair(seed)

      issuerBbsPublicKey <- bbsApi.blsPublicKeyToBbsKey(issuerKeys.pub, messageCount)

      //issuer signs messages
      signContext <- bbsApi.bbsSignContextInit()
      _ <- signContext.addMessages(messages)
      _ <- signContext.setSecretKey(issuerKeys.priv)
      _ <- printIt(signContext.setPublicKey(issuerBbsPublicKey))
      originalSig <- signContext.signature()

      nonce = Random.nextBytes(10)

      holderLink = messages.head
      //holder makes commitment
      blindCommitmentContext <- bbsApi.bbsBlindCommitmentContextInit()
      _ <- printIt(blindCommitmentContext.addMessage(0, holderLink))
      _ <- printIt(blindCommitmentContext.setPublicKey(issuerBbsPublicKey))
      _ <- printIt(blindCommitmentContext.setNonce(nonce))
      blindCommitment <- printIt(blindCommitmentContext.blindCommitment())

      //Issuer checks the holders send?
      verifyResult =
         for {
          verifyBlindCommitmentContext <- bbsApi.bbsVerifyBlindCommitmentContextInit()
          _ <- printIt(verifyBlindCommitmentContext.addBlinded(0))
          _ <- printIt(verifyBlindCommitmentContext.setPublicKey(issuerBbsPublicKey))
          _ <- printIt(verifyBlindCommitmentContext.setNonce(nonce))
          _ <- printIt(verifyBlindCommitmentContext.setProof(blindCommitment.outContext))
          res <- printIt(verifyBlindCommitmentContext.verify())
        } yield res

      _ = println(s"VerifyBlindCommitmentContextInit $verifyResult")

      _ = assert(verifyResult.unsafe, verifyResult)

      _ = println ("Start BlindSignContextInit")

      blindSignContext <- bbsApi.bbsBlindSignContextInit ()
      _ <- blindSignContext.addMessage (1, messages (1))
      _ <- blindSignContext.addMessage (2, messages (2))
      _ <- blindSignContext.addMessage (3, messages (3))
      _ <- blindSignContext.addMessage (4, messages (4))
      _ <- blindSignContext.addMessage (5, messages (5))
      _ <- blindSignContext.setPublicKey (issuerBbsPublicKey)
      _ <- blindSignContext.setSecretKey (issuerKeys.priv)
      _ <- blindSignContext.setCommitment (blindCommitment.commitment)
      blindSig <- blindSignContext.signature()

      unblindSig <- bbsApi.bbsUnblindSignature(blindSig, blindCommitment.blindingFactor)
      verifyContext <- bbsApi.bbsVerifyContextInit()
      //_ <- printIt(verifyContext.addMessage(Random.nextBytes(34))) So what is the point?
      _ <- printIt(verifyContext.setPublicKey(issuerBbsPublicKey))
      _ <- printIt(verifyContext.setSignature(unblindSig))
      v <- printIt(verifyContext.verify())

      _ = assert(v, v)
      //holder makes proof for 2 messages
      proofCtxt <- bbsApi.bbsCreateProofContextInit()
      _ <- proofCtxt.setPublicKey(issuerBbsPublicKey)
      revealOnly3 = messages.zipWithIndex.map {
        case (m, 0) => MessageWithProofType(m, ProofMessageType.Revealed)
        case (m, 3) => MessageWithProofType(m, ProofMessageType.Revealed)
        case (m, _) => MessageWithProofType(m, ProofMessageType.HiddenProofSpecificBlinding)
      }
      _ <- proofCtxt.addMessages(revealOnly3, blindCommitment.blindingFactor)
      _ <- proofCtxt.setSignature(unblindSig)
      _ <- proofCtxt.setNonce(nonce)
      proof <- printIt(proofCtxt.proof(), "proof")

      //verifier has messages and wants to prove who signed it
      //he needs the nonce,
      // ALL the messages in the proof context,
      // the public key
      // and the proof
      verifyProofContext <- printIt(bbsApi.bbsVerifyProofContextInit(), "bbsVerifyProofContextInit")
      //_ <- printIt(verifyProofContext.addMessage(messages(0)), "addMessage 0")
      _ <- printIt(verifyProofContext.addMessage(messages(3)), "addMessage 3")
      _ <- verifyProofContext.setPublicKey(issuerBbsPublicKey)
      _ <- verifyProofContext.setNonce(nonce)
      _ <- verifyProofContext.setProof(proof)
      isOk <- verifyProofContext.verify()

    } yield (isOk)


    println(s"$isOkResult")
    //require(isOkResult.getOrElse(false), "What?")

  }
}