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
import spray.routing.directives.{
  BasicDirectives,
  HeaderDirectives,
  RouteDirectives
}

/**
 * Provides utilities for signing and verification by the JSON Web Token (JWT).
 */
trait JwtDirectives {
  import BasicDirectives.{ extract, provide }
  import HeaderDirectives.optionalHeaderValueByName
  import RouteDirectives.reject

  /**
   * A `UserPassAuthenticator` which returns a JWS object if a given pair of
   * a user and a password is authenticated.
   *
   * Useful if combined with `BasicAuth` and an `authenticate` directive.
   * An inner route of an `authenticate` directive will receive a JWS object
   * (`JWSObject`) built by `claimBuilder` and signed by `signer`.
   *
   * @param authenticator
   *     The `UserPassAuthenticator` which authenticates a given pair of a user
   *     and a password.
   * @param claimBuilder
   *     Builds a claim set from a result of `authenticator`.
   * @param signer
   *     Signs a result of `claimBuilder`.
   * @param executionContext
   *     The execution context to run a `Future` returned from `authenticator`.
   */
  def jwtAuthenticator[T](authenticator: UserPassAuthenticator[T])
    (implicit claimBuilder: T => Option[JWTClaimsSet],
              signer: JWTClaimsSet => JWSObject,
              executionContext: ExecutionContext): UserPassAuthenticator[JWSObject] =
    authenticator(_) map {
      case Some(x) => claimBuilder(x) map { signer(_) }
      case None    => None
    }

  /** 
   * Verifies a token sent with an HTTP request.
   *
   * A token should be sent through the `Authorization` header like,
   * {{{
   * Authorization: Bearer JWT
   * }}}
   *
   * Thanks to [[JwtAuthorizationMagnet]], this directive will end up
   * the following form,
   * {{{
   * authorizeToken[T](privilege: JWTClaimsSet => Option[T])
   *   (implicit verifier: JWSObject => Option[JWTClaimsSet]): Directive1[T]
   * }}}
   *
   * And will
   *  1. Obtain the value associated with "Authorization" header.
   *  1. Extract a JWT from the "Authorization" header value.
   *  1. Verify the JWT with `verifier` and extract a claim set.
   *  1. Apply `privilege` to the claim set.
   *  1. Supply the result from `privilege` to the inner route.
   *
   * Will reject,
   *  - if no "Authorization" header is specified,
   *  - or if the "Authorization" header does not specify a JWT,
   *  - or if `verifier` cannot verify the JWT,
   *  - or if `privilege` rejects the claims set.
   *
   */
  def authorizeToken[T](magnet: JwtAuthorizationMagnet[T]): Directive1[T] = {
    val prefix = "Bearer "
    def extractJwt(value: String): Option[JWSObject] =
      if (value.startsWith(prefix))
        try
          Some(JWSObject.parse(value.substring(prefix.length)))
        catch {
          case _: ParseException => None
        }
      else
        None
    optionalHeaderValueByName("Authorization") flatMap { valueOpt =>
      valueOpt flatMap { value =>
        extractJwt(value) flatMap { token =>
          magnet.verifier(token) flatMap { token =>
            magnet.privilege(token)
          }
        }
      } match {
        case Some(result) => provide(result)
        case None         => reject(AuthorizationFailedRejection)
      }
    }
  }
}

/** The companion object of [[JwtDirectives]]. */
object JwtDirectives extends JwtDirectives

/**
 * Magnet which attracts parameters necessary for the `authorizeToken`
 * directive.
 */
case class JwtAuthorizationMagnet[T](privilege: JWTClaimsSet => Option[T])
  (implicit val verifier: JWSObject => Option[JWTClaimsSet])

/** Companion object of [[JwtAuthorizationMagnet]]. */
object JwtAuthorizationMagnet {
  /**
   * Implicitly converts a given privilege function into
   * a [[JwtAuthorizationMagnet]].
   *
   * @param privilege
   *     Returns a context dependent object if a given claim set has
   *     a privilege otherwise `None`.
   */
  implicit def fromPrivilege[T](privilege: JWTClaimsSet => Option[T])
    (implicit verifier: JWSObject => Option[JWTClaimsSet]): JwtAuthorizationMagnet[T] =
    JwtAuthorizationMagnet(privilege)
}

/**
 * Provides signature signer and verifier for JWS.
 *
 * @param algorithm
 *     The name of the signature algorithm.
 * @param secret
 *     The secret key for signature.
 */
case class JwtSignature(algorithm: JWSAlgorithm, secret: String) {
  /** The common header of JWS objects. */
  private val header = new JWSHeader(algorithm)

  /** The common signer for JWS objects. */
  private val signer = new MACSigner(secret.getBytes())

  /** The common verifier for JWS objects. */
  private val verifier = new MACVerifier(secret.getBytes())

  /**
   * The implicit signer for JWS objects.
   *
   * Signs a given claim set and returns a signed JWS object.
   */
  implicit def jwtSigner(claim: JWTClaimsSet): JWSObject = {
    val jwsObject = new JWSObject(header, new Payload(claim.toJSONObject()))
    jwsObject.sign(signer)
    jwsObject
  }

  /**
   * The implicit verifier for JWS objects.
   *
   * Verifies a given JWS object and returns a contained claim set.
   */
  implicit def jwtVerifier(token: JWSObject): Option[JWTClaimsSet] =
    if (token.verify(verifier))
      try
        Option(JWTClaimsSet.parse(token.getPayload().toJSONObject()))
      catch {
        case _: ParseException => None
      }
    else
      None
}

/**
 * A claim builder.
 *
 * You can chain multiple claim builders by `&&` operator.
 */
trait JwtClaimBuilder[T] extends (T => Option[JWTClaimsSet]) { self =>
  /**
   * Builds a claim.
   *
   * @param input
   *     The input for the claim builder.
   *     Usually an output from an authenticator.
   * @return
   *     The claim build from `input`.
   */
  def apply(input: T): Option[JWTClaimsSet];

  /**
   * Chains a specified claim builder function after this claim builder.
   *
   * Claims appended by `after` have precedence over the claims built by this
   * claim builder.
   *
   * @param after
   *     The claim builder which appends claims after this claim builder.
   * @return
   *     A new claim builder which builds a claim set by this claim builder and
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
   *     The first claim set.
   * @param second
   *     The second claim set.
   * @return
   *     A new claim set which has claims in both `first` and `second`.
   *     `None` if `first` or `second` is `None`.
   */
  protected def mergeClaims(first:  Option[JWTClaimsSet],
                            second: Option[JWTClaimsSet]): Option[JWTClaimsSet] = 
    for {
      claims1 <- first
      claims2 <- second
    } yield {
      val newClaims = new JSONObject(claims1.toJSONObject())
      newClaims.merge(claims2.toJSONObject())
      JWTClaimsSet.parse(newClaims)
    }
}

/** Companion object of [[JwtClaimBuilder]]. */
object JwtClaimBuilder {
  /**
   * Returns a claim builder which sets the "exp" field to an expiration time.
   *
   * @param duration
   *     The valid duration of a JWT.
   *     The minimum resolution is one minute.
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
   *     The issuer of a JWT.
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
   *     A function which extracts the subject from an input.
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
  implicit def toJwtClaimBuilder[T](f: T => Option[JWTClaimsSet]): JwtClaimBuilder[T] =
    new JwtClaimBuilder[T] {
      override def apply(input: T) = f(input)
    }
}

/**
 * A privilege which verifies a claim set.
 *
 * Instance of this trait can be passed as a `privilege` argument of the
 * `authorizeToken` directive.
 */
trait JwtClaimVerifier extends (JWTClaimsSet => Option[JWTClaimsSet]) { self =>
  /**
   * Verifies a specified claim set.
   *
   * @param claims
   *     The claim set to be verified.
   * @return
   *     The verified claim set. `None` if `claim` is not verified.
   */
  def apply(claims: JWTClaimsSet): Option[JWTClaimsSet]

  /**
   * Chains a specified privilege function after this claim verifier.
   *
   * `after` will not be applied if this claim verifier fails.
   *
   * @param after
   *     The privilege function to be applied after this claim verifier.
   * @return
   *     A new privilege which applies this claim verifier and then `after`.
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
   * Returns a privileging function which verifies the expiration time.
   *
   * If a specified claim set does not have "exp" field, verification of it
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

  /** Implicitly converts a claim verifier into a [[JwtClaimVerifier]]. */
  implicit def toJwtClaimVerifier(f: JWTClaimsSet => Option[JWTClaimsSet]) =
    new JwtClaimVerifier {
      override def apply(claims: JWTClaimsSet): Option[JWTClaimsSet] = f(claims)
    }
}
