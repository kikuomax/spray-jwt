package com.github.kikuomax.spray

/**
 * Provides utilities for signing and verification by the JSON Web Token (JWT).
 *
 * Only JSON Web Signature (JWS) is supported.
 *
 * Please refer to [[http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30 OAuth Working Group Draft]] for details on JWT.
 *
 * The implementation is powered by [[http://connect2id.com/products/nimbus-jose-jwt Nimbus JOSE + JWT]].
 *
 * ===Signing===
 *
 * Signing is supposed to be done when a Basic authentication has succeeded.
 * There is a function [[JwtDirectives.jwtAuthenticator]] which returns
 * a `UserPassAuthenticator` that authenticates a given pair of a user and
 * a password, builds a claim set and signs it.
 * Both claim set buildind and signing functions are implicitly given to
 * [[JwtDirectives.jwtAuthenticator]].
 *
 * [[JwtClaimBuilder]] helps defining a claim set building function.
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
 * The following is an example derived from [[http://spray.io/documentation/1.2.2/spray-routing/security-directives/authenticate/#authenticate an example of the authenticate directive]].
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
