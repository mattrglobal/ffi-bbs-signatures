enablePlugins(BuildInfoPlugin)
enablePlugins(JavaAppPackaging)


import scala.sys.process.Process
import scala.language.postfixOps
import shared.Shared._

scalaVersion := "2.13.10"

organization := "ce.iohk"

// Make these values available to the project source at compile time
buildInfoKeys ++= Seq[BuildInfoKey](
  "NameOfBbsSharedObject" -> BbsLibName,
  "NameOfShimSharedObject" -> NameOfShimSharedObject,
  "pathToNativeObjectsInJar" -> pathToNativeObjectsInJar,
  "TargetForBbsSharedObjectDownload" -> TargetForBbsSharedObjectDownload
)

libraryDependencies ++= Seq(
  "com.github.jnr" % "jnr-ffi" % "2.2.13",
  "org.scalatest" %% "scalatest" % "3.2.15" % Test
)

run / fork := true

//define the compile time tasks to build the shim
lazy val getBbsHeader = taskKey[Unit]("Download the bbs header if required")
lazy val buildShim = taskKey[Unit]("Build  the Anoncreds shim shared object")

buildShim := {
  Process("make" :: "-f" ::
    "GNUmakefile" ::
    "CPU=${os.arch}" ::
    s"SRC_DIR=$NativeCodeSourceFolder" ::
    s"SHIM_BUILD_DIR=$TargetForBbsSharedObjectDownload" ::
    s"RT_LOCATION_ANONCREDS_SO=$TargetForBbsSharedObjectDownload"
    :: Nil) !
}

getBbsHeader := {
  shared.Shared.downloadSharedObjectHeaderFile
}

(Compile / compile) := ((Compile / compile) dependsOn buildShim).value
(Compile / compile) := ((Compile / compile) dependsOn getBbsHeader).value

// Add the shim .so and the anoncreds .so to the packaged jar
Compile / packageBin / mappings += {
  (baseDirectory.value / TargetForBbsSharedObjectDownload / NameOfShimSharedObject) -> pathToNativeObjectsInJar.resolve(NameOfShimSharedObject).toString
}

Compile / packageBin / mappings += {
  (baseDirectory.value / bbsLibLocation) -> pathToNativeObjectsInJar.resolve(BbsLibName).toString
}


