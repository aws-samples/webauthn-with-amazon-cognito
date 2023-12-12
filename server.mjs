// init project
import AmazonCognitoIdentity from "amazon-cognito-identity-js";
import dotenv from "dotenv";
import express from "express";
import cookieParser from "cookie-parser";
import hbs from "hbs";
import authn from "./libs/authn.mjs";
import helmet from "helmet";
const app = express();
app.use(helmet());

app.set("view engine", "html");
app.engine("html", hbs.__express);
app.set("views", "./views");
app.use(cookieParser());
app.use(express.json());
app.use(express.static("public"));

app.use((req, res, next) => {
  if (
    req.get("x-forwarded-proto") &&
    req.get("x-forwarded-proto").split(",")[0] !== "https"
  ) {
    return res.redirect(301, `https://${req.get("host")}`);
  }
  req.schema = "https";
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.get("/", (req, res) => {
  res.set("Content-Security-Policy", "script-src 'self'  https://ajax.googleapis.com https://cdn.jsdelivr.net https://www.w3schools.com 'unsafe-inline';");
  res.set("Cross-Origin-Embedder-Policy", "require-corp");
  res.set("Cross-Origin-Opener-Policy", "same-origin");
  res.render("webauthn.html");
});

app.get("/webauthn", (req, res) => {
  res.render("webauthn.html");
});

app.use("/authn", authn);

// listen for req :)
const port = 8080;
const listener = app.listen(port, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
