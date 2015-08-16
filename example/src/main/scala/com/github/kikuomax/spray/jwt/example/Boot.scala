package com.github.kikuomax.spray.jwt.example

import akka.actor.{
  ActorSystem,
  Props
}
import akka.io.IO
import akka.pattern.ask
import akka.util.Timeout
import scala.concurrent.duration.DurationInt
import spray.can.Http

/** Runs an example service. */
object Boot extends App {
  implicit val system = ActorSystem("spray-jwt-example")

  val service = system.actorOf(Props[ExampleServiceActor], "example-service")

  implicit val timeout = Timeout(5.seconds)
  IO(Http) ? Http.Bind(service, interface = "localhost", port = 9090)
}
