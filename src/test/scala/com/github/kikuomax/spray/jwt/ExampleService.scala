package com.github.kikuomax.spray.jwt

import com.nimbusds.jose._
import net.minidev.json._
import scala.concurrent._
import scala.concurrent.duration._
import spray.routing._
import spray.routing.authentication._

/** An example service. */
trait ExampleService extends HttpService {
  import JwtDirectives._
  import JwtClaimBuilder._
  import JwtClaimVerifier._

  // you can use Actor's dispatcher as the execution context
  implicit val executionContext: ExecutionContext

  // imports implicit signing and verification functions in the scope
  val signature = JwtSignature(JWSAlgorithm.HS256, "chiave segreta")
  import signature._

  // an implicit claim set building function
  implicit val claimBuilder: String => Option[JSONObject] =
    claimSubject[String](identity) ~>
    claimIssuer("spray-jwt") ~>
    claimExpiration(30.minutes)

  // a user authentication function
  def myUserPassAuthenticator(userPass: Option[UserPass]): Future[Option[String]] =
    Future {
      if (userPass.exists(up => up.user == "John" && up.pass == "p4ssw0rd"))
        Some("John")
      else
        None
    }

  val route =
    path("authenticate") {
      authenticate(BasicAuth(jwtAuthenticator(myUserPassAuthenticator _), "secure site")) { jws =>
        complete(jws.serialize())
      }
    } ~
    path("verify") {
      // a privileging function
      def privilegeUser(claim: JSONObject): Option[String] =
        Option(claim.get("sub")) flatMap {
          case user: String if user == "John" => Some(user)
          case _                              => None
        }

      authorizeToken(verifyNotExpired && privilegeUser) { userName =>
        complete(s"The user is $userName")
      }
    }
}
