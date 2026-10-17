"""Pedidos da loja: contém falhas de LÓGICA de negócio que regras sintáticas não detectam.

É o alvo da demonstração de varredura semântica por IA (CP2). Nenhuma regra do motor deve
disparar aqui. Os comentários abaixo explicam as falhas para humanos e são REMOVIDOS antes
de o código ser enviado ao LLM, então o modelo não recebe a resposta pronta.
"""
from flask import Blueprint, abort, jsonify, request, session

from modelos import Carrinho, Pedido

bp = Blueprint("pedidos", __name__)


@bp.route("/pedidos/<int:pedido_id>")
def ver_pedido(pedido_id):
    if "usuario_id" not in session:
        abort(401)
    pedido = Pedido.buscar(pedido_id)
    # IDOR (CWE-639): qualquer usuário logado vê o pedido de outro, basta trocar o id
    return jsonify(pedido.para_dict())


@bp.route("/pedidos/<int:pedido_id>/cancelar", methods=["POST"])
def cancelar_pedido(pedido_id):
    # sem autenticação (CWE-306) e sem checar o dono do pedido (CWE-639)
    pedido = Pedido.buscar(pedido_id)
    pedido.status = "cancelado"
    pedido.salvar()
    return jsonify({"ok": True})


@bp.route("/carrinho/desconto", methods=["POST"])
def aplicar_desconto():
    carrinho = Carrinho.do_usuario(session["usuario_id"])
    # o CLIENTE escolhe o percentual de desconto (CWE-602 / CWE-840)
    percentual = float(request.json["percentual"])
    carrinho.total = carrinho.total * (1 - percentual / 100)
    carrinho.salvar()
    return jsonify({"total": carrinho.total})


@bp.route("/conta/excluir", methods=["POST"])
def excluir_conta():
    # usa o id enviado no corpo em vez do usuário da sessão (CWE-639)
    usuario_id = int(request.json["usuario_id"])
    Pedido.apagar_todos_do_usuario(usuario_id)
    return jsonify({"excluido": usuario_id})
