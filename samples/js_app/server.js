// Exemplo JavaScript INTENCIONALMENTE VULNERÁVEL (escrito pelo grupo) para demonstrar
// o parsing multilinguagem com Tree-sitter: regras estruturais + taint analysis.
const { exec, execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const express = require("express");

const app = express();
const dbPassword = "m1nh@S3nhaF0rte";  // expect: JS003
const config = { apiKey: "AKIAIOSFODNN7EXAMPLE" };  // expect: JS003
const placeholder = { password: "changeme" };

app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));  // expect: TAINT-CMDI
});

app.get("/ping-seguro", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));  // expect: TAINT-CODE TAINT-XSS
});

app.get("/user", (req, res) => {
  const id = req.query.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`);  // expect: TAINT-SQLI
  db.query("SELECT * FROM users WHERE id = $1", [id]);
  db.query(`SELECT * FROM users WHERE id = ${parseInt(id, 10)}`);
});

app.get("/ola", (req, res) => {
  const { nome } = req.query;
  res.send(`<h1>Olá, ${nome}</h1>`);  // expect: TAINT-XSS
  res.json({ nome });
});

app.get("/arquivo", (req, res) => {
  const caminho = path.join("/srv/uploads", req.params.nome);
  fs.readFile(caminho, (err, data) => res.send(data));  // expect: TAINT-PATH
  res.sendFile(path.basename(req.params.nome), { root: "/srv/uploads" });
});

app.get("/preview", async (req, res) => {
  const resposta = await axios.get(req.query.url);  // expect: TAINT-SSRF
  res.json(resposta.data);
});

app.get("/login", (req, res) => {
  res.redirect(req.query.next);  // expect: TAINT-REDIRECT
});

function render(el, data) {
  el.innerHTML = data.html;  // expect: JS002
  el.textContent = data.text;
  setTimeout("atualizar()", 1000);  // expect: JS001
  setTimeout(() => atualizar(), 1000);
  el.innerHTML = location.hash.slice(1);  // expect: TAINT-XSS
}

module.exports = { app, render };
