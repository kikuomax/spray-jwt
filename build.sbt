organization := "com.github.kikuomax"

name         := "spray-jwt"

version      := "0.0.3-SNAPSHOT"

crossScalaVersions := Seq("2.11.4", "2.10.4")

scalacOptions := Seq("-unchecked", "-feature", "-deprecation", "-encoding", "utf8")

libraryDependencies ++= {
  val sprayV = "1.3.2"
  Seq(
    "io.spray"          %% "spray-routing"   % sprayV,
    "io.spray"          %% "spray-testkit"   % sprayV % "test",
    "com.typesafe.akka" %% "akka-actor"      % "2.3.8",
    "com.nimbusds"      %  "nimbus-jose-jwt" % "3.5",
    "org.specs2"        %% "specs2-core"     % "2.3.13" % "test"
  )
}

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
