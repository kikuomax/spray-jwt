package com.github.kikuomax.spray.jwt

import com.nimbusds.jose.{
  JWSAlgorithm,
  JWSObject
}
import com.nimbusds.jwt.JWTClaimsSet
import java.util.Calendar
import org.specs2.mutable.Specification
import scala.concurrent.{
  ExecutionContext,
  Future
}
import scala.concurrent.duration.{
  Duration,
  SECONDS
}
import spray.routing.HttpService
import spray.routing.authentication.UserPass
import spray.testkit.Specs2RouteTest
import JwtClaimBuilder.claimExpiration

/** Specification of `JwtDirectives`. */
class JwtDirectivesSpec
  extends Specification with Specs2RouteTest with HttpService with JwtDirectives
{
  // uses the one provided by spray.testkit
  override def actorRefFactory = system

  // implicit execution context
  implicit val executionContext = system.dispatcher

  // creates signer and verifier
  val signature = JwtSignature(JWSAlgorithm.HS256, "thisHasGotToBeAtleast32BitsLong.")

  // claims set builder that builds a claims set valid for one second
  val oneSecondBuilder: String => Option[JWTClaimsSet] =
    claimExpiration(Duration(1, SECONDS))

  // route that builds a claims set valid for one second
  val oneSecondRoute =
    get {
      def authenticator = jwtAuthenticator(up => Future { up.map(_.user) })(
        oneSecondBuilder, signature.jwtSigner, executionContext)
      def authentication = authenticator(Some(UserPass("user", "pass"))).map {
        u => Right(u.get)
      }
      authenticate(authentication) { jws =>
        complete(jws.serialize())
      }
    }

  "One second claims set builder" should {
    "build claims set valid for one second" in {
      val now = Calendar.getInstance()
      val expireBefore = now.clone().asInstanceOf[Calendar]
      expireBefore.add(Calendar.SECOND, 2)  // in 2 seconds
      Get() ~> oneSecondRoute ~> check {
        val jws = JWSObject.parse(responseAs[String])
        val claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject())
        // expects claims set
        // should expire after now but in 2 seconds from `now`
        claims.getExpirationTime().after(now.getTime()) must beTrue
        claims.getExpirationTime().before(expireBefore.getTime()) must beTrue
      }
    }
  }
}
