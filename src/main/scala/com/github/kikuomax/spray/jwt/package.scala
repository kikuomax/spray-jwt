package com.github.kikuomax.spray

/**
 * Provides utilities for signing and verifying the JSON Web Token (JWT).
 *
 * Only JSON Web Signature (JWS) is supported.
 *
 * Please refer to [[http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30 OAuth Working Group Draft]] for details about JWT.
 *
 * The implementation is powered by [[http://connect2id.com/products/nimbus-jose-jwt Nimbus JOSE + JWT]].
 *
 * ===Signing===
 *
 * Signing is designed to be done when a Basic authentication succeeds.
 * The function [[JwtDirectives.jwtAuthenticator]] returns
 * a `UserPassAuthenticator` which authenticates a given pair of user and
 * password, builds a claims set and signs it.
 * Both claims set buildind and signing functions are implicitly given to
 * [[JwtDirectives.jwtAuthenticator]].
 *
 * [[JwtClaimBuilder]] helps defining a claims set building function.
 *
 * [[JwtSignature]] helps defining a signing function.
 *
 * ===Verification===
 *
 * There is a directive [[JwtDirectives.authorizeToken]] which verifies and
 * privileges a given JWT.
 * A verification function is implicitly given to
 * [[JwtDirectives.authorizeToken]].
 *
 * [[JwtSignature]] helps defining a verification function.
 *
 * [[JwtClaimVerifier]] helps defining a privileging function.
 *
 * ===Example===
 *
 * The following is an example derived from [[http://spray.io/documentation/1.2.2/spray-routing/security-directives/authenticate/#authenticate the example of the authenticate directive]].
 *
 * {{{
 * import JwtDirectives._
 * import JwtClaimBuilder._
 * import JwtClaimVerifier._
 *
 * // you can use Actor's dispatcher as the execution context
 * implicit val executionContext: ExecutionContext
 *
 * // imports implicit signing and verification functions in the scope
 * val signature = JwtSignature(JWSAlgorithm.HS256, "chiave segreta")
 * import signature._
 *
 * // an implicit claim set building function
 * implicit val claimBuilder: String => Option[JWTClaimsSet] =
 *   claimSubject[String](identity) &&
 *   claimIssuer("spray-jwt") &&
 *   claimExpiration(30.minutes)
 *
 * // a user authentication function
 * def myUserPassAuthenticator(userPass: Option[UserPass]): Future[Option[String]] =
 *   Future {
 *     if (userPass.exists(up => up.user == "John" && up.pass == "p4ssw0rd"))
 *       Some("John")
 *     else
 *       None
 *   }
 *
 * val route =
 *   path("authenticate") {
 *     authenticate(BasicAuth(jwtAuthenticator(myUserPassAuthenticator _), "secure site")) { jws =>
 *       complete(jws.serialize())
 *     }
 *   } ~
 *   path("verify") {
 *     // a privileging function
 *     def privilegeUser(claim: JWTClaimsSet): Option[String] =
 *       Option(claim.getSubject()) flatMap {
 *         case user: String if user == "John" => Some(user)
 *         case _                              => None
 *       }
 *
 *     authorizeToken(verifyNotExpired && privilegeUser) { userName =>
 *       complete(s"The user is $userName")
 *     }
 *   }
 * }}}
 *
 */
package object jwt
