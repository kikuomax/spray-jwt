var express = require('express');
var app = express();

// servers the contents in the `html` directory
app.use(express.static('html'));

var server = app.listen(8080, function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('Example service listening at http://%s:%s', host, port);
});
