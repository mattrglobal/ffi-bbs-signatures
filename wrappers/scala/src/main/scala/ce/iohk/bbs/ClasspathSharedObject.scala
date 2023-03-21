package ce.iohk.bbs

import buildinfo.BuildInfo

import java.nio.file.{Files, Path}

object ClasspathSharedObject {

  def removeLibPrefixAndSuffix(libFileName: String): String =
    libFileName.substring("lib".length, libFileName.length - ".so".length)

  def namesOfSharedObjectsToLoad: Seq[String] = Seq(
    removeLibPrefixAndSuffix(BuildInfo.NameOfBbsSharedObject),
    removeLibPrefixAndSuffix(BuildInfo.NameOfShimSharedObject))

  def createTempFolderWithExtractedLibs: Path = {
    val result = Files.createTempDirectory(".scala_bbs")
    val pathToBbsSO = Path.of("/", BuildInfo.pathToNativeObjectsInJar).resolve(BuildInfo.NameOfBbsSharedObject)
    val pathToBbsShimSO = Path.of("/", BuildInfo.pathToNativeObjectsInJar).resolve(BuildInfo.NameOfShimSharedObject)
    extractToTempFile(pathToBbsSO, result)
    extractToTempFile(pathToBbsShimSO, result)
    result
  }

  /**
   *
   * @param pathToResource full path to resource including file name
   * @return the path the file name is at (name included)
   */
  private def extractToTempFile(pathToResource: Path, tempPath: Path): Path = {

    val in = this.getClass.getResourceAsStream(pathToResource.toString)

    try {
      require(Option(in).isDefined, s"Cannot get resource $pathToResource as stream")
      val newLibFile = tempPath.resolve(pathToResource.getFileName)
      newLibFile.toFile.deleteOnExit()
      val byteCount = Files.copy(in, newLibFile)
      require(byteCount > 0, s"Copy of $pathToResource results in $byteCount bytes copied?")
      newLibFile
    } finally {
      Option(in) foreach (_.close())
    }

  }

}
