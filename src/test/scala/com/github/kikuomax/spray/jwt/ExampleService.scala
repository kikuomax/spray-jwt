package com.github.kikuomax.spray.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import scala.concurrent.{
  ExecutionContext,
  Future
}
import scala.concurrent.duration.DurationInt
import spray.routing.HttpService
import spray.routing.authentication.{
  BasicAuth,
  UserPass
}

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
  implicit val claimBuilder: String => Option[JWTClaimsSet] =
    claimSubject[String](identity) &&
    claimIssuer("spray-jwt") &&
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
      def privilegeUser(claim: JWTClaimsSet): Option[String] =
        Option(claim.getSubject()) flatMap {
          case user: String if user == "John" => Some(user)
          case _                              => None
        }

      authorizeToken(verifyNotExpired && privilegeUser) { userName =>
        complete(s"The user is $userName")
      }
    }
}
