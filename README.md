*spray-jwt* is a set of utilities for [spray.io](http://spray.io), which perform signing and verification of a JSON Web Token (JWT).

Getting Started
===============

Add the following dependency,

	dependentLibraries += "com.github.kikuomax" %% "spray-jwt" % "0.0.1-SNAPSHOT"

Binaries for Scala 2.10.x and 2.11.x are provided.

Example
=======

Please refer to [ExampleService](src/test/scala/com/github/kikuomax/spray/jwt/ExampleService.scala).

JWT Library
===========

[Nimbus JOSE + JWT](http://connect2id.com/products/nimbus-jose-jwt) is used for generating and verifying JWTs.

License
=======

[MIT License](http://opensource.org/licenses/MIT)
