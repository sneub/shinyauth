const functions = require("firebase-functions");
const admin = require("firebase-admin");
const cors = require("cors");
const express = require("express");
const { ethers } = require("ethers");
const md5 = require("md5");

admin.initializeApp(functions.config().firebase);

const app = express();

var corsOptions = {
  origin: "*",
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

// This obviously would not live here, but we're just testing a concept...
const APPS = [
  {
    appName: "Test App",
    clientId: "abc",
    clientSecret: "123",
  },
];

async function verifyMessage({ address, message, signature }) {
  const signerAddr = await ethers.utils.verifyMessage(message, signature);
  return signerAddr === address;
}

function generateToken({ address }) {
  const now = Date.now();
  return md5(`${now}:${address}`);
}

app.post("/login", cors(corsOptions), async (req, res) => {
  const { address, message, signature } = req.body;
  const verified = await verifyMessage({ address, message, signature });

  if (verified) {
    const refreshToken = await generateToken(address);
    const accessToken = await generateToken(address);

    await admin.firestore().collection("sessions").doc(accessToken).set({
      datetime: new Date(),
      refreshToken,
      accessToken,
      wallet: address,
    });

    res.json({ refreshToken, accessToken });
  } else {
    res.statusCode = 403;
    res.json("Unauthorized");
  }
});

app.post("/verify", cors(corsOptions), async (req, res) => {
  const { clientId, clientSecret, accessToken } = req.body;

  if (!clientId || !clientSecret) {
    res.statusCode = 400;
    res.json({ message: "missing_ids" });
  }

  const app = APPS.find((a) => a.clientId === clientId);

  if (!app) {
    res.statusCode = 400;
    res.json({ message: "app_not_found" });
  }

  if (app.clientSecret !== clientSecret) {
    res.statusCode = 400;
    res.json({ message: "wrong_secret" });
  }

  const session = await admin
    .firestore()
    .collection("sessions")
    .doc(accessToken)
    .get()
    .then((doc) => doc.data());

  if (!session) {
    res.json({ message: "session_does_not_exist" });
  }

  const now = Math.floor(Date.now() / 1000);
  const sessionTime = Math.floor(session.datetime.toDate().getTime() / 1000);

  if (now - sessionTime > 3600) {
    res.json({ status: "invalid", reason: "session_expired" });
  }

  res.json({
    status: "ok",
    data: {
      email: `${session.wallet}@shiny.xyz`,
    },
  });
});

exports.auth = functions.https.onRequest(app);
