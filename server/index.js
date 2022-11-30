const secp = require("ethereum-cryptography/secp256k1");
const { toHex, hexToBytes } = require("ethereum-cryptography/utils");
const { getRandomBytesSync } = require("ethereum-cryptography/random");

const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {};

// Generate random key pair with balance
for (let i = 0; i < 5; i++) {
  const privateKey = secp.utils.randomPrivateKey();
  const pubKey = secp.getPublicKey(privateKey).slice(-20);
  const hPrivKey = toHex(privateKey);
  const hPubKey = `0x${toHex(pubKey)}`;

  balances[hPubKey] = getRandomBytesSync(1)[0]; // uint8array

  console.log({
    privateKey: hPrivKey,
    publicKey: hPubKey,
    balance: balances[hPubKey],
  });
}

const handledSignatures = new Set();

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sender, recipient, amount, signature, uuid, bit } = req.body;

  if (handledSignatures.has(signature)) {
    console.log("signature was already handled");
    return res.status(400).send({ message: "Invalid signature" });
  }

  handledSignatures.add(signature);

  // rebuild the signature
  const msg = {
    amount,
    uuid,
    recipient,
  };

  const msgHash = Buffer.from(JSON.stringify(msg));
  const recoveredPublicKey = secp.recoverPublicKey(msgHash, signature, bit);

  if (`0x${toHex(recoveredPublicKey.slice(-20))}` !== sender) {
    return res.status(400).send({ message: "Invalid sender" });
  }

  const isSigned = secp.verify(signature, msgHash, recoveredPublicKey);

  if (!isSigned) {
    return res.status(400).send({ message: "Invalid signature" });
  }

  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
