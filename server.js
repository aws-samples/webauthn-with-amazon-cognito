// init project
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
require('dotenv');
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const authn = require('./libs/authn');
const helmet = require('helmet');
const app = express();
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            'script-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net https://ajax.googleapis.com'],
            'script-src-attr': ["'self'", "'unsafe-inline'"],
            'style-src': ["'self'", "'unsafe-inline'", 'https://*.googleapis.com https://www.w3schools.com'],
            'connect-src': ["'self'", 'https://cognito-idp.us-west-2.amazonaws.com/' ],
            'img-src': ['https:', 'data:'],
        },
    },
}));


app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
  if (req.get('x-forwarded-proto') &&
     (req.get('x-forwarded-proto')).split(',')[0] !== 'https') {
    return res.redirect(301, `https://${req.get('host')}`);
  }
  req.schema = 'https';
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, res) => {
  res.render('webauthn.html');
});

app.get('/webauthn', (req, res) => {
  res.render('webauthn.html');
});

app.use('/authn', authn);

// listen for req :)
const port = 8080;
const listener = app.listen(port, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
