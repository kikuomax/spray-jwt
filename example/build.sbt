organization := "com.github.kikuomax"

name := "spray-jwt-example"

version := "0.1.1"

scalaVersion := "2.11.4"

scalacOptions := Seq("-unchecked", "-feature", "-deprecation", "-encoding", "utf8")

resolvers += "Sonatype OSS Snapshots" at
  "https://oss.sonatype.org/content/repositories/snapshots"

libraryDependencies ++= {
  val sprayV = "1.3.2"
  val akkaV = "2.3.8"
  Seq(
    "io.spray"            %% "spray-can"                % sprayV,
    "io.spray"            %% "spray-routing-shapeless2" % sprayV,
    "com.typesafe.akka"   %% "akka-actor"               % "2.3.8",
    "com.github.kikuomax" %% "spray-jwt-shapeless2"     % "0.0.4"
  )
}

Revolver.settings
