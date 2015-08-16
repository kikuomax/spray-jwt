*spray-jwt* is a set of utilities for [spray.io](http://spray.io), which perform signing and verification of a JSON Web Token (JWT).

Getting Started
===============

Add the following dependency to your `build.sbt`,

```
libraryDependencies += "com.github.kikuomax" %% "spray-jwt" % "0.0.1"
```

Binaries for Scala 2.10.x and 2.11.x are provided.

If you are using [shapeless 2](https://github.com/milessabin/shapeless); i.e., `spray-routing-shapeless2`, please try the following,

```
libraryDependencies += "com.github.kikuomax" %% "spray-jwt-shapeless2" % "0.0.1"
```

Example
=======

The following example is derived from the example code in the documentation for the `authenticate` directive.

```scala
import com.github.kikuomax.spray.jwt.JwtDirectives._
import com.github.kikuomax.spray.jwt.JwtClaimBuilder._
import com.github.kikuomax.spray.jwt.JwtClaimVerifier._
import com.github.kikuomax.spray.jwt.JwtSignature
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
```

You also can find an example application in the [example](/example) directory.
Please read the [README](/example/README.md) for the example.

JWT Library
===========

[Nimbus JOSE + JWT](http://connect2id.com/products/nimbus-jose-jwt) is used for generating and verifying JWTs.

License
=======

[MIT License](http://opensource.org/licenses/MIT)
