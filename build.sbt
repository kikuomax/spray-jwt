organization := "com.github.kikuomax"

name         := "spray-jwt"

version      := "0.0.2-SNAPSHOT"

crossScalaVersions := Seq("2.10.4", "2.11.4")

scalacOptions := Seq("-unchecked", "-feature", "-deprecation", "-encoding", "utf8")

libraryDependencies ++= Seq(
  "io.spray"          %% "spray-routing"   % "1.3.2",
  "com.typesafe.akka" %% "akka-actor"      % "2.3.8",
  "com.nimbusds"      %  "nimbus-jose-jwt" % "3.5"
)

publishMavenStyle := true

publishTo := {
  val prefix = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at prefix + "content/repositories/snapshots")
  else
    Some("releases" at prefix +"service/local/staging/deploy/maven2")
}

publishArtifact in Test := false

licenses := Seq("MIT License" -> url("http://opensource.org/licenses/MIT"))

homepage := Some(url("https://github.com/kikuomax/spray-jwt"))

pomExtra := (
  <scm>
    <url>https://github.com/kikuomax/spray-jwt.git</url>
    <connection>scm:git:https://github.com/kikuomax/spray-jwt.git</connection>
  </scm>
  <developers>
    <developer>
      <id>kikuomax</id>
      <name>Kikuo Emoto</name>
      <url>https://github.com/kikuomax</url>
    </developer>
  </developers>
)
