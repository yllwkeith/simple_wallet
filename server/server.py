import re
import decimal

from flask import Flask, abort, request, jsonify, make_response, g as flask_storage

from auth import auth
from db import User, Wallet, Transaction, init_app
from errors import AlreadyExist, NonEmptyWallet, InsufficientFunds, WalletLimit, TransactionError

app = Flask(__name__)


@app.route('/wallets', methods=['GET'])
@auth.login_required
def get_wallets():
    wallets = flask_storage.current_user.wallets
    result = {
        'wallets': [{'address': wallet.address, 'value': str(wallet.value)} for wallet in wallets]
    }

    return make_response(jsonify(result), 200)


@app.route('/wallets', methods=['POST'])
@auth.login_required
def new_wallet():
    wallet = Wallet.create(flask_storage.current_user)
    return make_response(jsonify({'address': wallet.address}), 201)


@app.route('/wallets/<string:address>', methods=['GET'])
@auth.login_required
def get_wallet(address):
    wallet = flask_storage.current_user.wallets.filter_by(address=address).first()

    if not wallet:
        return make_response(jsonify({'error': 'Wallet does not exist'}), 404)

    return make_response(jsonify({'address': wallet.address, 'value': str(wallet.value)}))


@app.route('/wallets/<string:address>', methods=['DELETE'])
@auth.login_required
def delete_wallet(address):
    wallet = flask_storage.current_user.wallets.filter_by(address=address).first()

    if not wallet:
        return make_response(jsonify({'error': 'Wallet does not exist'}), 404)

    try:
        wallet.delete()
    except NonEmptyWallet:
        return make_response(jsonify({'error': 'Non-empty wallet'}), 400)

    return make_response(jsonify({'message': 'Wallet deleted', 'address': wallet.address}), 200)


@app.route('/user', methods=['POST'])
def new_user():
    if not request.is_json:
        abort(400)

    username = request.json.get('username')
    password = request.json.get('password')

    if not (username and password):
        return make_response(jsonify({'error': 'Username and password are required'}), 400)

    try:
        User.create(username, password)
    except AlreadyExist:
        return make_response(jsonify({'error': 'Username already taken'}), 409)

    return make_response(jsonify({'message': 'User successfully created', 'username': username}), 201)


@app.route('/transaction', methods=['POST'])
@auth.login_required
def transfer_funds():
    if not request.is_json:
        abort(400)

    recipient = request.json.get('to')
    sender = request.json.get('from')
    amount = request.json.get('amount')

    if not (recipient and sender and amount):
        return make_response(jsonify({'error': 'from, to and amount fields are required'}), 400)

    if type(amount) != str or not re.fullmatch(r'\d*?.\d{2}', amount):
        return make_response(
            jsonify({'error': 'Amount should be string with two decimal points, separated with dot'}), 400,
        )

    amount = decimal.Decimal(amount)

    min_transfer_amount = app.config['MIN_TRANSFER_AMOUNT']
    if amount < decimal.Decimal(min_transfer_amount):
        return make_response(jsonify({'error': 'Amount must be at least {}'.format(min_transfer_amount)}), 400)

    recipient = Wallet.query.filter_by(address=recipient).first()
    sender = flask_storage.current_user.wallets.filter_by(address=sender).first()

    if not (recipient and sender):
        return make_response(jsonify({'error': 'Wallet does not exist'}), 400)

    if recipient.id == sender.id:
        return make_response(jsonify({'error': 'Wallets should be not equal'}), 400)

    try:
        transaction = Transaction.create(recipient, sender, amount)
        transaction.process()
    except InsufficientFunds:
        return make_response(jsonify({'error': 'insufficient funds'}), 400)
    except (WalletLimit, TransactionError):
        return make_response(jsonify({'error': 'transaction failed'}), 400)

    return make_response(jsonify({'message': 'transaction processed successfully'}), 200)


if __name__ == '__main__':
    from config import DATABASE_URI, HOST, PORT, DEBUG, MIN_TRANSFER_AMOUNT, MAX_WALLET_VALUE

    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['MIN_TRANSFER_AMOUNT'] = MIN_TRANSFER_AMOUNT
    app.config['MAX_WALLET_VALUE'] = MAX_WALLET_VALUE
    init_app(app)

    app.run(host=HOST, port=PORT, debug=DEBUG)
