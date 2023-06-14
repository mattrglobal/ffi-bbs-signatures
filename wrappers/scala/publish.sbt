
organization := "ce.iohk"

javacOptions ++= Seq("-source", "11", "-target", "11")

ThisBuild / licenses := List("APL2" -> url("https://www.apache.org/licenses/LICENSE-2.0.txt"))
ThisBuild / description := "A scala wrapper of the BBS library"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/input-output-hk/ce-ffi-bbs-signatures"),
    "scm:git@github.com/input-output-hk/ce-ffi-bbs-signatures.git"
  )
)

ThisBuild / developers := List(
  Developer("mcsherrylabs", "Alan McSherry", "alan.mcsherry@iohk.io", url("https://github.com/mcsherrylabs"))
)

// Remove all additional repository other than Maven Central from POM
ThisBuild / pomIncludeRepository := { _ => false }

publishMavenStyle := true

ThisBuild / versionScheme := Some("early-semver")

ThisBuild / publishTo := {
  val nexus = "https://nexus.iog.solutions/"
  if (isSnapshot.value)
    Some("maven-snapshot" at nexus + "repository/maven-snapshot")
  else
    Some("maven-release"  at nexus + "repository/maven-release")
}

ThisBuild / credentials += sys.env.get("IOG_NEXUS_USER").map(userName => Credentials(
  "Sonatype Nexus Repository Manager",
  "nexus.iog.solutions",
  userName,
  sys.env.getOrElse("IOG_NEXUS_PASS", ""))
).getOrElse(
  Credentials(Path.userHome / ".ivy2" / ".credentials")
)

ThisBuild / version := sys.env.getOrElse("GITHUB_REF_NAME", "0.1.4-SNAPSHOT").replaceAll("/", "_")

//usePgpKeyHex("F4ED23D42A612E27F11A6B5AF75482A04B0D9486")
