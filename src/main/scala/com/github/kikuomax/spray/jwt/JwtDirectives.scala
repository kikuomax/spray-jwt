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
import java.text.ParseException
import java.util.Calendar
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
   * An inner route of an `authenticate` directive will receive a JWS
   * (`JSONObject`) built by `claimBuilder` and signed by `signer`.
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
    (implicit claimBuilder: T => Option[JSONObject],
              signer: JSONObject => JWSObject,
              executionContext: ExecutionContext): UserPassAuthenticator[JWSObject] =
    authenticator(_) map {
      case Some(data) => claimBuilder(data) map { signer(_) }
      case None       => None
    }

  /** 
   * Verifies a token sent with an HTTP request.
   *
   * A token should be sent through the `Authorization` header like,
   * {{{
   * Authorization: Bearer JWT
   * }}}
   *
   * Thanks to [[JwtAuthorizationMagnet]], this directive takes arguments
   * similar to the following,
   * {{{
   * authorizeToken[T](privilege: JSONObject => Option[T])
   *   (implicit verifier: JWSObject => Option[JSONObject]): Directive1[T]
   * }}}
   *
   * And will
   *  1. Obtain the value associated with "Authorization" header.
   *  1. Extract a JWT from the "Authorization" header value.
   *  1. Verify the JWT with `verifier`.
   *  1. Apply `privilege` to the JWT.
   *  1. Supply the result from `privilege` to the inner route.
   *
   * Will reject,
   *  - if no "Authorization" header is specified,
   *  - or if the "Authorization" header does not specify a JWT,
   *  - or if `verifier` cannot verify the JWT,
   *  - or if `privilege` rejects the JWT
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
case class JwtAuthorizationMagnet[T](privilege: JSONObject => Option[T])
  (implicit val verifier: JWSObject => Option[JSONObject])

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
  implicit def fromPrivilege[T](privilege: JSONObject => Option[T])
    (implicit verifier: JWSObject => Option[JSONObject]): JwtAuthorizationMagnet[T] =
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
  implicit def jwtSigner(claim: JSONObject): JWSObject = {
    val jwsObject = new JWSObject(header, new Payload(claim))
    jwsObject.sign(signer)
    jwsObject
  }

  /**
   * The implicit verifier for JWS objects.
   *
   * Verifies a given JWS object and returns a contained claim set.
   */
  implicit def jwtVerifier(token: JWSObject): Option[JSONObject] =
    if (token.verify(verifier))
      Option(token.getPayload().toJSONObject())
    else
      None
}

/**
 * A claim builder.
 *
 * You can chain multiple claim builders by `~` operator.
 */
trait JwtClaimBuilder[T] extends (T => Option[JSONObject]) { self =>
  /**
   * Builds a claim.
   *
   * @param input
   *     The input for the claim builder.
   *     Usually an output from an authenticator.
   * @return
   *     The claim build from `input`.
   */
  def apply(input: T): Option[JSONObject];

  /**
   * Chains a specified claim builder after this claim builder.
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
  def ~>(after: T => Option[JSONObject]): T => Option[JSONObject] =
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
  protected def mergeClaims(first:  Option[JSONObject],
                            second: Option[JSONObject]): Option[JSONObject] = 
    for {
      claims1 <- first
      claims2 <- second
    } yield {
      val newClaims = new JSONObject(claims1)
      newClaims.merge(claims2)
      newClaims
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
  def claimExpiration[T](duration: Duration): T => Option[JSONObject] =
    input => {
      val validUntil = Calendar.getInstance()
      validUntil.add(Calendar.MINUTE, duration.toMinutes.toInt)
      val claims = new JSONObject()
      val seconds: Long = validUntil.getTimeInMillis() / 1000
      claims.put("exp", new java.lang.Long(seconds))
      Some(claims)
    }

  /**
   * Returns a claim builder which sets the "iss" field to a specified string.
   *
   * @param issuer
   *     The issuer of a JWT.
   */
  def claimIssuer[T](issuer: String): T => Option[JSONObject] =
    input => {
      val claims = new JSONObject()
      claims.put("iss", issuer)
      Some(claims)
    }

  /**
   * Returns a claim builder which sets the "sub" field.
   *
   * @param subject
   *     A function which extracts the subject from an input.
   */
  def claimSubject[T](subject: T => String): T => Option[JSONObject] =
    input => {
      val claims = new JSONObject()
      claims.put("sub", subject(input))
      Some(claims)
    }

  /**
   * Implicitly converts a claim builder function into a [[JwtClaimBuilder]].
   */
  implicit def toJwtClaimBuilder[T](f: T => Option[JSONObject]): JwtClaimBuilder[T] =
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
trait JwtClaimVerifier extends (JSONObject => Option[JSONObject]) { self =>
  /**
   * Verifies a specified claim set.
   *
   * @param claims
   *     The claim set to be verified.
   * @return
   *     The verified claim set. `None` if `claim` is not verified.
   */
  def apply(claims: JSONObject): Option[JSONObject]

  /**
   * Chains a privilege after this claim verifier.
   *
   * `after` will not be applied if this claim verifier fails.
   *
   * @param after
   *     The privilege to be applied after this claim verifier.
   * @return
   *     A new privilege which applies this claim verifier and then `after`.
   */
  def &&[T](after: JSONObject => Option[T]): JSONObject => Option[T] =
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
  def verifyNotExpired: JSONObject => Option[JSONObject] =
    claims => {
      def isValid(validUntil: Long) =
        Calendar.getInstance().getTimeInMillis() / 1000 <= validUntil
      claims.get("exp") match {
        case validUntil: Number if isValid(validUntil.longValue()) =>
          Some(claims)
        case _ =>
          None
      }
    }

  /** Implicitly converts a claim verifier into a [[JwtClaimVerifier]]. */
  implicit def toJwtClaimVerifier(f: JSONObject => Option[JSONObject]) =
    new JwtClaimVerifier {
      override def apply(claims: JSONObject): Option[JSONObject] = f(claims)
    }
}
