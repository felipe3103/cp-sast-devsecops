// Exemplo JavaScript INTENCIONALMENTE VULNERÁVEL (escrito pelo grupo) para demonstrar
// o parsing multilinguagem com Tree-sitter.
const { exec, execFile } = require("child_process");
const express = require("express");

const app = express();
const dbPassword = "m1nh@S3nhaF0rte";  // expect: JS003
const config = { apiKey: "AKIAIOSFODNN7EXAMPLE" };  // expect: JS003
const placeholder = { password: "changeme" };

app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));  // expect: JS004
});

app.get("/ping-seguro", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));  // expect: JS001
});

app.get("/user", (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);  // expect: JS005
  db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
});

function render(el, data) {
  el.innerHTML = data.html;  // expect: JS002
  el.textContent = data.text;
  setTimeout("atualizar()", 1000);  // expect: JS001
}

module.exports = { app, render };
