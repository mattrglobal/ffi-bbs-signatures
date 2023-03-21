package shared

import java.nio.file.{Files, Path}

object Shared {

  //val AnonCredsTag = "v0.1.0-dev.8"
  //val AnonCredsLibArchiveName = "library-linux-x86_64.tar.gz"
  val BbsLibName = "libbbs.so"
  val BbsLibHeaderName = "bbs.h"
  val TargetForBbsSharedObjectDownload = "native-lib/linux"
  val NativeCodeSourceFolder = "src/main/c"

  def tempPathForSharedObject: Path = Files.createTempFile("so_download", "gzip")

  def targetPathForBbsSharedObjectDownload: Path =
    Files.createDirectories(
      Path.of(TargetForBbsSharedObjectDownload)
    )

  val pathToBbsHeaderOrigin = Path.of("../../include/")

  def bbsLibLocation: String = targetPathForBbsSharedObjectDownload.resolve(BbsLibName).toString

  def bbsLibHeaderLocation: Path = Path.of(NativeCodeSourceFolder, BbsLibHeaderName)

  def downloadSharedObjectHeaderFile: Unit = {
    //https://github.com/hyperledger/anoncreds-rs/blob/v0.1.0-dev.8/include/libanoncreds.h
    if (bbsLibHeaderLocation.toFile.exists()) {
      println(s"$bbsLibHeaderLocation exists, no download necessary. Delete this file to trigger download if you've changed the tag.")
    } else {
      println(s"Copy $pathToBbsHeaderOrigin $BbsLibHeaderName to $bbsLibHeaderLocation.")
      Files.copy(pathToBbsHeaderOrigin.resolve(BbsLibHeaderName), bbsLibHeaderLocation)
    }
  }


  private def toStandardString(s: String): String = s.toLowerCase.replace("\\s+", "_")

  def pathToNativeObjectsInJar: Path =
    Path.of("NATIVE",
      toStandardString(sys.props("os.arch")),
      toStandardString(sys.props("os.name")))


  val NameOfShimSharedObject = "libbbs-shim.so"

}
