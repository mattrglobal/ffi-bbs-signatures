import buildinfo.BuildInfo
import ce.iohk.bbs.BbsPlusOps._
import ce.iohk.bbs.{BbsPlusNative, PrintUtil, ProofMessageType}
import org.scalatest.flatspec.AnyFlatSpec

import java.util.Base64
import scala.util.Random

/**
 * https://github.com/mattrglobal/ffi-bbs-signatures/blob/bba4ff32cf3c659b380237ca856266499e025705/tests/bbs_test.c
 */
class CopyOfEndToEndTests extends AnyFlatSpec {

  "A copy of the bbs tests" should "run to completion" in {
    EndToEnd.runTests()
  }
}


object EndToEnd extends PrintUtil {

  def runTests(): Unit = {

    val api = BbsPlus(BbsPlusNative(
      Seq(BuildInfo.TargetForBbsSharedObjectDownload, ".")
    ))

    val seed = Array(0.toByte)

    val messages: Array[Array[Byte]] = ((0 to 4) map (_ => Random.nextBytes(10))).toArray

    val sigAndKp = for {
      kp <- api.createBlsKeyPair(seed)
      _ = println(s"PRIV ${kp.priv.length} PUB ${kp.pub.length}")
      pubKeyStr = Base64.getEncoder.encodeToString(kp.pub)
      privKeyStr = Base64.getEncoder.encodeToString(kp.priv)
      _ = println(s"pub ($pubKeyStr priv $privKeyStr")
      bbsKey <- api.blsPublicKeyToBbsKey(kp.pub, messages.length)
      signContext <- api.bbsSignContextInit()

      _ <- signContext.setPublicKey(bbsKey)
      _ <- signContext.setSecretKey(kp.priv)
      _ <- signContext.addMessages(messages)
      sig <- signContext.signature()

    } yield (sig, kp, bbsKey)

    val (sig, kp, bbsKey) = sigAndKp.unsafe
    println(s"Blind sig size is correct? ${sig.length} == ${api.bbsBlindSigSize()}")

    val nonce = Random.nextBytes(60)

    println("Start VerifyContextInit")
    val simpleVerifyResult = for {
      verifyContext <- api.bbsVerifyContextInit()
      _ <- printIt(verifyContext.setSignature(sig))
      _ <- printIt(verifyContext.setPublicKey(bbsKey))
      _ <- printIt(verifyContext.addMessages(messages))
      result <- printIt(verifyContext.verify())
    } yield result

    println(s"simpleVerifyResult ${simpleVerifyResult.unsafe}")

    println("Start BlindCommitmentContextInit")
    val bcResult = for {
      blindCommitmentContext <- api.bbsBlindCommitmentContextInit()
      _ <- printIt(blindCommitmentContext.addMessage(0, messages(0)))
      _ <- printIt(blindCommitmentContext.setPublicKey(bbsKey))
      _ <- printIt(blindCommitmentContext.setNonce(nonce))
      result <- printIt(blindCommitmentContext.blindCommitment())
    } yield result

    println(bcResult.unsafe)

    val blindContext = bcResult.unsafe

    println("Start VerifyBlindCommitmentContextInit")
    val verifyResult = for {
      verifyBlindCommitmentContext <- api.bbsVerifyBlindCommitmentContextInit()
      _ <- printIt(verifyBlindCommitmentContext.addBlinded(0))
      _ <- printIt(verifyBlindCommitmentContext.setPublicKey(bbsKey))
      _ <- printIt(verifyBlindCommitmentContext.setNonce(nonce))
      _ <- printIt(verifyBlindCommitmentContext.setProof(blindContext.outContext))
      res <- printIt(verifyBlindCommitmentContext.verify())
    } yield res

    require(verifyResult.unsafe, "VerifyBlindCommitmentContextInit?")

    printIt(verifyResult)

    println("Start BlindSignContextInit")
    val signResult = for {
      blindSignContext <- api.bbsBlindSignContextInit()
      _ <- printIt(blindSignContext.addMessage(1, messages(1)))
      _ <- printIt(blindSignContext.addMessage(2, messages(2)))
      _ <- printIt(blindSignContext.addMessage(3, messages(3)))
      _ <- printIt(blindSignContext.addMessage(4, messages(4)))
      _ <- printIt(blindSignContext.setPublicKey(bbsKey))
      _ <- printIt(blindSignContext.setSecretKey(kp.priv))
      _ <- printIt(blindSignContext.setCommitment(blindContext.commitment))
      sig <- blindSignContext.signature()

    } yield sig

    printIt(signResult)

    println("Start VerifyContextInit")
    val unblindSigResult = for {
      sig <- signResult
      unblindSig <- api.bbsUnblindSignature(sig, blindContext.blindingFactor)
      verifyContext <- api.bbsVerifyContextInit()
      _ <- printIt(verifyContext.addMessages(messages))
      _ <- printIt(verifyContext.setPublicKey(bbsKey))
      _ <- printIt(verifyContext.setSignature(unblindSig))
      _ <- printIt(verifyContext.verify())

    } yield unblindSig

    println(s" ${unblindSigResult.unsafe.length}")


    println("Start CreateProofContextInit")
    val proofRes = for {
      createProofContext <- api.bbsCreateProofContextInit()
      _ <- printIt(createProofContext.addMessage(messages(0), ProofMessageType.Revealed, blindContext.blindingFactor))
      _ <- printIt(createProofContext.addMessage(messages(1), ProofMessageType.Revealed, blindContext.blindingFactor))
      _ <- printIt(createProofContext.addMessage(messages(2), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor))
      _ <- printIt(createProofContext.addMessage(messages(3), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor))
      _ <- printIt(createProofContext.addMessage(messages(4), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor))
      unblindSig <- unblindSigResult
      _ <- printIt(createProofContext.setSignature(unblindSig))
      _ <- printIt(createProofContext.setPublicKey(bbsKey))
      _ <- printIt(createProofContext.setNonce(nonce))
      proof <- createProofContext.proof()
    } yield proof

    println("Start VerifyProofContextInit")
    val res = for {
      verifyProofContext <- api.bbsVerifyProofContextInit()
      _ <- printIt(verifyProofContext.addMessage(messages(0)))
      _ <- printIt(verifyProofContext.addMessage(messages(1)))
      proof <- proofRes
      _ <- printIt(verifyProofContext.setProof(proof))
      _ <- printIt(verifyProofContext.setPublicKey(bbsKey))
      _ <- printIt(verifyProofContext.setNonce(nonce))
      res <- printIt(verifyProofContext.verify())
    } yield res

    println(s"Res $res")

    println("Create new proof context 2..")
    val context2Proof = for {
      createProofContext <- api.bbsCreateProofContextInit()
      _ <- createProofContext.addMessage(messages(0), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor)
      _ <- createProofContext.addMessage(messages(1), ProofMessageType.Revealed, blindContext.blindingFactor)
      _ <- createProofContext.addMessage(messages(2), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor)
      _ <- createProofContext.addMessage(messages(3), ProofMessageType.Revealed, blindContext.blindingFactor)
      _ <- createProofContext.addMessage(messages(4), ProofMessageType.HiddenProofSpecificBlinding, blindContext.blindingFactor)
      unblinded <- unblindSigResult
      _ <- createProofContext.setSignature(unblinded)
      _ <- createProofContext.setPublicKey(bbsKey)
      _ <- createProofContext.setNonce(nonce)
      proof <- createProofContext.proof()
    } yield proof

    val done = for {
      verifyProofContext <- api.bbsVerifyProofContextInit()
      _ <- printIt(verifyProofContext.addMessage(messages(1)))
      _ <- printIt(verifyProofContext.addMessage(messages(3)))
      proof <- context2Proof
      _ <- printIt(verifyProofContext.setProof(proof))
      _ <- printIt(verifyProofContext.setPublicKey(bbsKey))
      _ <- printIt(verifyProofContext.setNonce(nonce))
      v <- printIt(verifyProofContext.verify())
    } yield v

    require(done == Right(true), "Should be true?")
  }

}
