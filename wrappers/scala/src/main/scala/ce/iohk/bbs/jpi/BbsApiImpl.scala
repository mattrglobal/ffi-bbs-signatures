package ce.iohk.bbs.jpi

import ce.iohk.bbs.{BbsPlusNative, BbsVerifyBlindCommitmentContext, MessageWithProofType, ProofMessageType}
import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsPlus, BlindCommitment}

import java.security.SecureRandom
import scala.jdk.CollectionConverters.CollectionHasAsScala

object BbsApiImpl {
  def apply(pathsToSearch: java.util.List[String], libsToLoad: java.util.List[String]): BbsApiImpl = {
    val native = BbsPlusNative(
      pathsToSearch.asScala.toSeq,
      libsToLoad.asScala.toSeq
    )
    new BbsApiImpl(native)
  }

  def apply(): BbsApiImpl = new BbsApiImpl(BbsPlusNative())

}
class BbsApiImpl(bbsPlusNative: BbsPlusNative) extends BbsJpi {

  lazy val api = BbsPlus(bbsPlusNative)
  private val seed = Array.emptyByteArray

  private def throwOnError[T](e: EExternError[T]): T = e match {
    case Left(e) => throw e
    case Right(value) => value
  }

  override def createKeyPair(): KeyPair = {
    val kp = throwOnError(api.createBlsKeyPair(seed))
    new KeyPair(kp.priv, kp.pub)
  }

  override def createBbsPublicKey(blsPublicKey: Array[Byte],
                                  numMessages: Int): Array[Byte] = {
    throwOnError(api.blsPublicKeyToBbsKey(blsPublicKey, numMessages))
  }

  override def verify(messages: Array[Array[Byte]],
                      signature: Array[Byte],
                      publicKey: Array[Byte]): Boolean = {
    val result: EExternError[Boolean] = for {
      c <- api.bbsVerifyContextInit()
      _ <- c.addMessages(messages)
      _ <- c.setPublicKey(publicKey)
      _ <- c.setSignature(signature)
      v <- c.verify()
    } yield v

    throwOnError(result)
  }

  override def sign(messages: Array[Array[Byte]], keyPair: KeyPair): Array[Byte] = {
    val result = for {
      c <- api.bbsSignContextInit()
      _ <- c.addMessages(messages)
      _ <- c.setPublicKey(keyPair.getPublicKey)
      _ <- c.setSecretKey(keyPair.getPrivateKey)
      s <- c.signature()
    } yield s

    throwOnError(result)
  }

  override def createLinkSecretsCommitment(
                        publicKey: Array[Byte],
                        nonce: Array[Byte],
                        messages: Array[Array[Byte]]): BlindCommitment = {
    val result = for {
      b <- api.bbsBlindCommitmentContextInit()
      _ <- b.addMessages(messages)
      _ <- b.setPublicKey(publicKey)
      _ <- b.setNonce(nonce)
      c <- b.blindCommitment()
    } yield c

    throwOnError(result)
  }

  override def createLinkSecretCommitment(
                                  publicKey: Array[Byte],
                                  nonce: Array[Byte],
                                  message: Array[Byte]): BlindCommitment = {
    createLinkSecretsCommitment(publicKey, nonce, Array(message))
  }

  private def addBlindedIndices(indices: Seq[Int],
                              verifyBlindCommitmentContext: BbsVerifyBlindCommitmentContext): EExternError[BbsVerifyBlindCommitmentContext] = {
    if(indices.isEmpty) Right(verifyBlindCommitmentContext)
    else {
      verifyBlindCommitmentContext
        .addBlinded(indices.head)
        .flatMap(acc => addBlindedIndices(indices.tail,acc))
    }
  }

  override def verifyBlindCommitment(publicKey: Array[Byte],
                             nonce: Array[Byte],
                             commitmentProof: Array[Byte]): Boolean = {
    verifyBlindCommitments(publicKey, nonce, java.util.List.of(Integer.getInteger("0")), commitmentProof)
  }

  override def verifyBlindCommitments(publicKey: Array[Byte],
                            nonce: Array[Byte],
                            commitmentIndices: java.util.List[Integer],
                            commitmentProof: Array[Byte]): Boolean = {
    val verifyResult = for {
      verifyBlindCommitmentContext <- api.bbsVerifyBlindCommitmentContextInit()
      _ <- addBlindedIndices(commitmentIndices.asScala.toSeq.map(_.toInt), verifyBlindCommitmentContext)
      _ <- verifyBlindCommitmentContext.setPublicKey(publicKey)
      _ <- verifyBlindCommitmentContext.setNonce(nonce)
      _ <- verifyBlindCommitmentContext.setProof(commitmentProof)
      res <- verifyBlindCommitmentContext.verify()
    } yield res

    throwOnError(verifyResult)
  }

  override def blindSign(
                          publicKey: Array[Byte],
                          privateKey: Array[Byte],
                          blindCommitment: Array[Byte],
                          messages: java.util.List[Array[Byte]],
                          startingIndex: Int): Array[Byte] = {

    val msgs = messages.asScala.toSeq

    val signResult = for {
      blindSignContext <- api.bbsBlindSignContextInit()
      _ <- blindSignContext.addMessages(startingIndex, msgs)
      _ <- blindSignContext.setPublicKey(publicKey)
      _ <- blindSignContext.setSecretKey(privateKey)
      _ <- blindSignContext.setCommitment(blindCommitment)
      sig <- blindSignContext.signature()

    } yield sig

    throwOnError(signResult)
  }

  override def createProof(blindSig: Array[Byte],
                  nonce: Array[Byte],
                  publicKey: Array[Byte],
                  blindingFactor: Array[Byte],
                  messages:java.util.List[MessageWithProofType]): Array[Byte] = {
    val msgsScala = messages.asScala
    val proofResult = for {

      unblindSig <- api.bbsUnblindSignature(blindSig, blindingFactor)
      verifyContext <- api.bbsVerifyContextInit()
      _ <- verifyContext.addMessages(msgsScala.map(_.msg).toArray)
      _ <- verifyContext.setPublicKey(publicKey)
      _ <- verifyContext.setSignature(unblindSig)
      _ <- verifyContext.verify()
      createProofContext <- api.bbsCreateProofContextInit()
      _ <- createProofContext.addMessages(msgsScala.toSeq, blindingFactor)
      _ <- createProofContext.setSignature(unblindSig)
      _ <- createProofContext.setPublicKey(publicKey)
      _ <- createProofContext.setNonce(nonce)
      proof <- createProofContext.proof()
    } yield proof

    throwOnError(proofResult)
  }

  override def verifyProof(
                 proof: Array[Byte],
                 publicKey: Array[Byte],
                 nonce: Array[Byte],
                   presentedMessages: java.util.List[Array[Byte]]): Boolean = {

    val res = for {
      verifyProofContext <- api.bbsVerifyProofContextInit()
      _ <- verifyProofContext.addMessages(presentedMessages.asScala.toSeq)
      _ <- verifyProofContext.setProof(proof)
      _ <- verifyProofContext.setPublicKey(publicKey)
      _ <- verifyProofContext.setNonce(nonce)
      res <- verifyProofContext.verify()
    } yield res

    throwOnError(res)
  }
}
