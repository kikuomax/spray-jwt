*spray-jwt-example* provides an example service for *spray-jwt*.

This example provides a simple interface to authenticate users and records messages.

Prerequisites
=============

You need the following software installed,
 - [Git](https://git-scm.com)
 - [sbt](http://www.scala-sbt.org)
 - [Node.js](https://nodejs.org)

Building
========

 1. Clone the repository `https://github.com/kikuomax/spray-jwt.git` and move down to it.

	```shell
	git clone https://github.com/kikuomax/spray-jwt.git
	cd spray-jwt
	```

 2. Move down to the `example` directory.

	```shell
	cd example
	```

 3. Builds the project by sbt.

	```shell
	sbt compile
	```

 4. Install necessary modules for *Node.js*.

	```shell
	npm install
	```

Running a service
=================

The example consists of an API and client interface services.

 1. Runs an API service on sbt.

	```shell
	sbt
	> re-start
	```

	The API service will be listening at `http://localhost:9090`.

 2. Runs a client interface service on *Node.js*.

	```shell
	node service.js
	```

	The client interface service will be listening at `http://localhost:8080`.

 3. Open `http://localhost:8080` on your browser.

The following pairs of username and password can be used,

Username | Password | Privilege
-------- | -------- | ---------
John     | p4ssw0rd | RW
Alice    | key      | RW
Bob      | chiave   | R
