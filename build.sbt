organization := "com.github.kikuomax"

name         := "spray-jwt"

version      := "0.0.1-SNAPSHOT"

scalaVersion  := "2.11.4"

scalacOptions := Seq("-unchecked", "-feature", "-deprecation", "-encoding", "utf8")

libraryDependencies ++= Seq(
  "io.spray"          %% "spray-routing"   % "1.3.2",
  "com.typesafe.akka" %% "akka-actor"      % "2.3.8",
  "com.nimbusds"      %  "nimbus-jose-jwt" % "3.5"
)

useGpg := true

publishMavenStyle := true

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
