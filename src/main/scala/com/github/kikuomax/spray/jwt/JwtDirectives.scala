package com.github.kikuomax.spray.jwt

import com.nimbusds.jose.{
  JWSAlgorithm,
  JWSHeader,
  JWSObject,
  Payload
}
import com.nimbusds.jose.crypto.{
  MACSigner,
  MACVerifier
}
import com.nimbusds.jwt.JWTClaimsSet
import java.text.ParseException
import java.util.{
  Calendar,
  Date
}
import net.minidev.json.JSONObject
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.Duration
import scala.language.implicitConversions
import spray.routing.{
  AuthorizationFailedRejection,
  Directive1
}
import spray.routing.authentication.{
  UserPass,
  UserPassAuthenticator
}
import spray.routing.directives.BasicDirectives.{
  extract,
  provide
}
import spray.routing.directives.CookieDirectives.optionalCookie
import spray.routing.directives.HeaderDirectives.optionalHeaderValueByName
import spray.routing.directives.RouteDirectives.reject

/**
 * Provides utilities for building, signing and verification of a JSON Web
 * Token (JWT).
 */
trait JwtDirectives {
  /**
   * `UserPassAuthenticator` that returns a JWS object if a given pair of
   * a user and a password is authenticated.
   *
   * Useful if combined with `BasicAuth` and an `authenticate` directive.
   * An inner route of an `authenticate` directive will receive a JSON Web
   * Signature object (`JWSObject`) built by `claimsBuilder` and signed by
   * `signer`.
   *
   * @tparam T
   *     Outcome type of `authenticator`.
   * @param authenticator
   *     Authenticates a given pair of a user and a password.
   * @param claimsBuilder
   *     Builds a claims set from the authentication result.
   * @param signer
   *     Signs the claims set and creates a JSON Web Signature.
   * @param executionContext
   *     Execution context where a `Future` returned from `authenticator` runs.
   */
  def jwtAuthenticator[T](authenticator: UserPassAuthenticator[T])
    (implicit claimsBuilder: T => Option[JWTClaimsSet],
              signer: JWTClaimsSet => JWSObject,
              executionContext: ExecutionContext):
      UserPassAuthenticator[JWSObject] =
        authenticator(_) map {
          case Some(x) => claimsBuilder(x) map { signer(_) }
          case None => None
        }

  /** 
   * Verifies a token sent with an HTTP request.
   *
   * Thanks to [[JwtAuthorizationMagnet]], this directive works like the
   * following functions,
   * {{{
   * authorizeToken[T](verifier: JWTClaimsSet => Option[T])
   *   (implicit confirmer: JWSObject => Option[JWTClaimsSet]): Directive1[T]
   *
   * authorizeToken[T](extractor: Directive1[Option[JWSObject]],
   *                   verifier: JWTClaimsSet => Option[T])
   *   (implicit confirmer: JWSObject => Option[JWTClaimsSet]): Directive1[T]
   * }}}
   *
   * This directive
   *  1. Extracts a JWS from the request through `extractor`.
   *  1. Confirms the signature of the JWS and extracts the claims set by
   *     `confirmer`.
   *  1. Verifies the claims set by `verifier`.
   *  1. Supplies the result from `verifier` to the inner route.
   *
   * Rejects
   *  - if `extractor` cannot extract a JWS from the request,
   *  - or if `confirmer` cannot confirm the signature of a JWS,
   *  - or if `confirmer` cannot extract the claims set from a JWS,
   *  - or if `verifier` rejects the claims set.
   *
   */
  def authorizeToken[T](magnet: JwtAuthorizationMagnet[T]): Directive1[T] =
    magnet.extractor flatMap { jwsOpt =>
      jwsOpt flatMap { jws =>
        magnet.confirmer(jws) flatMap { token =>
          magnet.verifier(token)
        }
      } match {
        case Some(result) => provide(result)
        case _ => reject(AuthorizationFailedRejection)
      }
    }
}

/** Companion object of [[JwtDirectives]]. */
object JwtDirectives extends JwtDirectives

/**
 * Magnet that attracts parameters necessary for the `authorizeToken`
 * directive.
 *
 * @constructor
 * @tparam T
 *     Outcome type of `verifier`.
 * @param extractor
 *     Extracts a JSON Web Signature (JWS) from an HTTP request.
 * @param confirmer
 *     Confirms the signature of the JWS and extracts the claims set.
 * @param verifier
 *     Verifiers the claims set and converts it to an application-specific
 *     object.
 */
case class JwtAuthorizationMagnet[T](
  extractor: Directive1[Option[JWSObject]],
  confirmer: JWSObject => Option[JWTClaimsSet],
  verifier: JWTClaimsSet => Option[T])

/** Companion object of [[JwtAuthorizationMagnet]]. */
object JwtAuthorizationMagnet {
  /**
   * Implicitly converts a given verifier function into
   * a [[JwtAuthorizationMagnet]].
   *
   * @param verifier
   *     Returns an application-specific object if a given claims set is
   *     verified, otherwise `None`.
   */
  implicit def fromVerifier[T](verifier: JWTClaimsSet => Option[T])
    (implicit confirmer: JWSObject => Option[JWTClaimsSet]):
      JwtAuthorizationMagnet[T] = JwtAuthorizationMagnet(
        JwsExtractor.extractJwsFromAuthorizationHeader,
        confirmer,
        verifier)

  /**
   * Implicitly converts a given pair of an extractor directive and a verifier
   * function into a [[JwtAuthorizationMagnet]].
   *
   * @param ev
   *     `ev._1` extracts a JWS from an HTTP request.
   *     `ev._2` verifies a given claims set and returns an application-specific
   *     object.
   */
  implicit def fromExtractor[T](ev: (Directive1[Option[JWSObject]],
                                     JWTClaimsSet => Option[T]))
    (implicit confirmer: JWSObject => Option[JWTClaimsSet]):
      JwtAuthorizationMagnet[T] =
        JwtAuthorizationMagnet(ev._1, confirmer, ev._2)
}

/**
 * Provides signature signer and verifier for JWS.
 *
 * @constructor
 * @param algorithm
 *     Name of the signature algorithm.
 * @param secret
 *     Secret key for the signature algorithm.
 */
case class JwtSignature(algorithm: JWSAlgorithm, secret: String) {
  /** Common header of JWS objects. */
  private val header = new JWSHeader(algorithm)

  /** Common signer for JWS objects. */
  private val signer = new MACSigner(secret.getBytes())

  /** Common verifier for JWS objects. */
  private val verifier = new MACVerifier(secret.getBytes())

  /**
   * Implicit signer for JWS objects.
   *
   * Signs a given claims set and returns a signed JWS object.
   */
  implicit def jwtSigner(claim: JWTClaimsSet): JWSObject = {
    val jwsObject = new JWSObject(header, new Payload(claim.toJSONObject()))
    jwsObject.sign(signer)
    jwsObject
  }

  /**
   * Implicit confirmer for JWS objects.
   *
   * Confirms the signature of a given JWS object and returns its claims set.
   */
  implicit def jwtConfirmer(token: JWSObject): Option[JWTClaimsSet] = {
    if (token.verify(verifier)) {
      try {
        Option(JWTClaimsSet.parse(token.getPayload().toJSONObject()))
      } catch {
        case _: ParseException => None
      }
    } else {
      None
    }
  }
}

/**
 * Claim builder.
 *
 * You can chain multiple claim builders by `&&` operator.
 */
trait JwtClaimBuilder[T] extends (T => Option[JWTClaimsSet]) { self =>
  /**
   * Builds a claim.
   *
   * @param input
   *     Input for the claim builder.
   *     Usually an output from an authenticator.
   * @return
   *     Claims set build from `input`.
   */
  def apply(input: T): Option[JWTClaimsSet];

  /**
   * Chains a specified claim builder function after this claim builder.
   *
   * Claims appended by `after` have precedence over the claims built by this
   * claim builder.
   *
   * @param after
   *     Claim builder that appends claims after this claim builder.
   * @return
   *     New claim builder which builds a claims set by this claim builder and
   *     `after`.
   */
  def &&(after: T => Option[JWTClaimsSet]): T => Option[JWTClaimsSet] =
    input => mergeClaims(self(input), after(input))

  /**
   * Merges specified two claim sets.
   *
   * Claims in `second` have precedence over claims in `first`.
   *
   * @param first
   *     First claims set.
   * @param second
   *     Second claims set.
   * @return
   *     New claims set that has claims in both `first` and `second`.
   *     `None` if `first` or `second` is `None`.
   */
  protected def mergeClaims(first:  Option[JWTClaimsSet],
                            second: Option[JWTClaimsSet]):
    Option[JWTClaimsSet] = {
      for {
        claims1 <- first
        claims2 <- second
      } yield {
        val newClaims = new JSONObject(claims1.toJSONObject())
        newClaims.merge(claims2.toJSONObject())
        JWTClaimsSet.parse(newClaims)
      }
    }
}

/** Companion object of [[JwtClaimBuilder]]. */
object JwtClaimBuilder {
  /**
   * Returns a claim builder which sets the "exp" field to an expiration time.
   *
   * @param duration
   *     Valid duration of a JWT.
   *     Minimum resolution is one minute.
   */
  def claimExpiration[T](duration: Duration): T => Option[JWTClaimsSet] =
    input => {
      val validUntil = Calendar.getInstance()
      validUntil.add(Calendar.MINUTE, duration.toMinutes.toInt)
      val claims = new JWTClaimsSet()
      claims.setExpirationTime(validUntil.getTime())
      Some(claims)
    }

  /**
   * Returns a claim builder which sets the "iss" field to a specified string.
   *
   * @param issuer
   *     Issuer of a JWT.
   */
  def claimIssuer[T](issuer: String): T => Option[JWTClaimsSet] =
    input => {
      val claims = new JWTClaimsSet()
      claims.setIssuer(issuer)
      Some(claims)
    }

  /**
   * Returns a claim builder which sets the "sub" field.
   *
   * @param subject
   *     Extracts the subject from an input.
   */
  def claimSubject[T](subject: T => String): T => Option[JWTClaimsSet] =
    input => {
      val claims = new JWTClaimsSet()
      claims.setSubject(subject(input))
      Some(claims)
    }

  /**
   * Implicitly converts a claim builder function into a [[JwtClaimBuilder]].
   */
  implicit def toJwtClaimBuilder[T](f: T => Option[JWTClaimsSet]):
    JwtClaimBuilder[T] =
      new JwtClaimBuilder[T] {
        override def apply(input: T) = f(input)
      }
}

/** Provides common JWS extractors. */
object JwsExtractor {
  /**
   * Extracts a JWS from "Authorization" header of an HTTP request.
   *
   * A JWS should be sent through "Authorization" header like,
   * {{{
   * Authorization: Bearer JWS
   * }}}
   *
   * @return
   *     Directive that extracts a JWS from "Authorization" header of an HTTP
   *     request.
   *     This directive provides `None` if an HTTP request does not have
   *     "Authorization" header, or if the value of "Authorization" header is
   *     invalid.
   */
  val extractJwsFromAuthorizationHeader: Directive1[Option[JWSObject]] =
    optionalHeaderValueByName("Authorization") flatMap { tokenOpt =>
      provide {
        tokenOpt flatMap { token =>
          val prefix = "Bearer "
          if (token.startsWith(prefix))
            try
              Some(JWSObject.parse(token.substring(prefix.length)))
            catch {
              case _: ParseException => None
            }
          else
            None
        }
      }
    }

  /**
   * Extracts a JWS from a cookie that has a given name.
   *
   * @param name
   *     Name of a cookie from which a JWS is to be extracted.
   * @return
   *     Directive that extracts a JWS from a cookie given by `name`.
   *     This directive provides `None` if no cookie corresponding to `name`
   *     exists, or if the value of the cookie is invalid.
   */
  def extractJwsFromCookie(name: String): Directive1[Option[JWSObject]] =
    optionalCookie(name) flatMap { ckOpt =>
      provide {
        ckOpt flatMap { ck =>
          try
            Some(JWSObject.parse(ck.content))
          catch {
            case _: ParseException => None
          }
        }
      }
    }
}

/**
 * Verifies a claims set.
 *
 * Instance of this trait can be passed as a `verifier` argument of the
 * `authorizeToken` directive.
 */
trait JwtClaimVerifier extends (JWTClaimsSet => Option[JWTClaimsSet]) { self =>
  /**
   * Verifies a given claims set.
   *
   * @param claims
   *     Claims set to be verified.
   * @return
   *     Verified claims set. `None` if `claims` is not verified.
   */
  def apply(claims: JWTClaimsSet): Option[JWTClaimsSet]

  /**
   * Chains a given claim verifier after this claim verifier.
   *
   * `after` will not be applied if this claim verifier fails.
   *
   * @param after
   *     Claim verifier to be applied after this claim verifier.
   * @return
   *     New claim verifier that applies this claim verifier and then `after`.
   */
  def &&[T](after: JWTClaimsSet => Option[T]): JWTClaimsSet => Option[T] =
    claims =>
      for {
        first  <- self(claims)
        second <- after(first)
      } yield (second)
}

/** Companion object of [[JwtClaimVerifier]]. */
object JwtClaimVerifier {
  /**
   * Returns a claim verifier that tests the expiration time.
   *
   * If a specified claims set does not have "exp" field, verification of it
   * fails; i.e., returns `None`.
   */
  def verifyNotExpired: JWTClaimsSet => Option[JWTClaimsSet] =
    claims => {
      def isValid(validUntil: Date) =
        Calendar.getInstance().getTime().compareTo(validUntil) <= 0
      Option(claims.getExpirationTime()) match {
        case Some(validUntil) if isValid(validUntil) => Some(claims)
        case _                                       => None
      }
    }

  /**
   * Implicitly converts a claim verifier function into a [[JwtClaimVerifier]].
   */
  implicit def toJwtClaimVerifier(f: JWTClaimsSet => Option[JWTClaimsSet]) =
    new JwtClaimVerifier {
      override def apply(claims: JWTClaimsSet): Option[JWTClaimsSet] = f(claims)
    }
}
