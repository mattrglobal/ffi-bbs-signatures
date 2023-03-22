import EndToEnd.printIt
import buildinfo.BuildInfo
import ce.iohk.bbs.{BbsPlusNative, MessageWithProofType, ProofMessageType}
import ce.iohk.bbs.BbsPlusOps._

import java.nio.charset.{Charset, StandardCharsets}
import scala.util.Random
import ce.iohk.bbs.PrintUtil._

object Main {

  def main(args: Array[String]): Unit = {

    println("Create a presentation")

    /**
     * I want to create a message  and sign it and then prove
     */

    val messageCount = 10
    val messages = ((0 until messageCount) map (_ => Random.nextBytes(50))).toArray

    val bbsApi = BbsPlus(
      BbsPlusNative(
        Seq(BuildInfo.TargetForBbsSharedObjectDownload, ".")
      )
    )


    val seed: Array[Byte] = Random.nextBytes(128)

    val isOkResult = for {

      //Issuer creates keys
      keys <- bbsApi.createBlsKeyPair(seed)

      bbsKey <- bbsApi.blsPublicKeyToBbsKey(keys.pub, messageCount)

      //issuer signs messages
      signContext <- bbsApi.bbsSignContextInit()
      _ <- signContext.addMessages(messages)
      _ <- signContext.setSecretKey(keys.priv)
      _ <- printIt(signContext.setPublicKey(bbsKey))
      sig <- signContext.signature()

      nonce = Random.nextBytes(10)

      //issuer makes commitment
      blindCommitmentContext <- bbsApi.bbsBlindCommitmentContextInit()
      _ <- printIt(blindCommitmentContext.addMessages(messages))
      _ <- printIt(blindCommitmentContext.setPublicKey(bbsKey))
      _ <- printIt(blindCommitmentContext.setNonce(nonce))
      blindCommitment <- printIt(blindCommitmentContext.blindCommitment())


      //issuer makes proof for 2 messages
      proofCtxt <- bbsApi.bbsCreateProofContextInit()
      _ <- proofCtxt.setPublicKey(bbsKey)
      revealOnly3 = messages.zipWithIndex.map {
        case (m, 3) => MessageWithProofType(m, ProofMessageType.Revealed)
        case (m, 5) => MessageWithProofType(m, ProofMessageType.Revealed)
        case (m, _) => MessageWithProofType(m, ProofMessageType.HiddenProofSpecificBlinding)
      }
      _ <- proofCtxt.addMessages(revealOnly3, blindCommitment.blindingFactor)
      _ <- proofCtxt.setSignature(sig)
      _ <- proofCtxt.setNonce(nonce)
      proof <- printIt(proofCtxt.proof(), "proof")

      //verifier has messages and wants to prove who signed it
      //he needs the nonce,
      // ALL the messages in the proof context,
      // the public key
      // and the proof
      verifyProofContext <- printIt(bbsApi.bbsVerifyProofContextInit(), "bbsVerifyProofContextInit")
      _ <- printIt(verifyProofContext.addMessage(messages(3)), "addMessage 3")
      _ <- printIt(verifyProofContext.addMessage(messages(5)), "addMessage 5")
      _ <- verifyProofContext.setPublicKey(bbsKey)
      _ <- verifyProofContext.setNonce(nonce)
      _ <- verifyProofContext.setProof(proof)
      isOk <- verifyProofContext.verify()

    } yield (isOk)


    println(s"$isOkResult")
    //require(isOkResult.getOrElse(false), "What?")

  }
}