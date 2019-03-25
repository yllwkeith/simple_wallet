import decimal
import os
import tempfile
import unittest
from base64 import b64encode

from config import MIN_TRANSFER_AMOUNT, MAX_WALLET_VALUE
from db import Wallet, Transaction, User, init_app, db as database
from server import app


class ServerTestCase(unittest.TestCase):

    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.testing = True
        self.client = app.test_client()
        app.config['MIN_TRANSFER_AMOUNT'] = MIN_TRANSFER_AMOUNT
        app.config['MAX_WALLET_VALUE'] = MAX_WALLET_VALUE

        init_app(app)

    @staticmethod
    def refresh_from_db(obj):
        database.session.add(obj)
        database.session.refresh(obj)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])


class UnauthTestCase(ServerTestCase):
    def test_registration(self):
        response = self.client.post('/user', json={'username': 'test', 'password': 'test'})
        self.assertEqual(response.status_code, 201)

        response = self.client.post('/user', json={'username': 'test', 'password': 'test'})
        self.assertEqual(response.status_code, 409)

    def test_wallets_endpoints(self):
        response = self.client.get('/wallets')
        self.assertEqual(response.status_code, 401)

        response = self.client.post('/wallets')
        self.assertEqual(response.status_code, 401)

        response = self.client.get('/wallets/1')
        self.assertEqual(response.status_code, 401)

        response = self.client.post('/wallets/1')
        self.assertEqual(response.status_code, 405)

        response = self.client.delete('/wallets/1')
        self.assertEqual(response.status_code, 401)

    def test_transaction_endpoint(self):
        response = self.client.get('/transaction')
        self.assertEqual(response.status_code, 405)

        response = self.client.post('/transaction')
        self.assertEqual(response.status_code, 401)


class UserTestCase(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.username = 'test'
        self.password = 'test'

        self.user = self.create_user()

    def create_user(self, **kwargs):
        username = kwargs.get('username', self.username)
        password = kwargs.get('password', self.password)

        return User.create(username, password)

    def get_auth_headers(self):
        username = self.username.encode('utf-8')
        password = self.username.encode('utf-8')
        return {
            "Authorization": "Basic {user}".format(
                user=b64encode(b':'.join((username, password))).decode('utf-8')
            )
        }

    def test_login(self):
        # i don't have a login endpoint due using HTTP basic auth, so I request wallets to check that I can login
        response = self.client.get('/wallets', headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 200)


class WalletsTestCase(UserTestCase):
    def setUp(self):
        super().setUp()
        self.wallet = self.create_wallet()

    def create_wallet(self, user=None):
        if not user:
            user = self.user

        return Wallet.create(user)

    def test_create_wallet(self):
        response = self.client.post('/wallets', headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 201)

    def test_delete_wallet(self):
        response = self.client.delete('/wallets/{}'.format(self.wallet.address), headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 200)

    def test_get_wallet(self):
        response = self.client.get('/wallets/{}'.format(self.wallet.address), headers=self.get_auth_headers())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['address'], self.wallet.address)
        self.assertEqual(response.json['value'], str(self.wallet.value))

        response = self.client.get('/wallets', headers=self.get_auth_headers())
        self.refresh_from_db(self.user)

        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(
            response.json,
            {
                'wallets': [
                    {
                        'address': wallet.address,
                        'value': str(wallet.value),
                    }
                    for wallet in self.user.wallets
                ]
            },
        )


class TransactionTestCase(WalletsTestCase):
    def setUp(self):
        super().setUp()

        self.sender_wallet = self.create_wallet()
        self.sender_wallet.value = decimal.Decimal('1.00')
        database.session.commit()

        self.recipient_wallet = self.create_wallet()
        self.sent_amount = decimal.Decimal('1.00')

        self.refresh_from_db(self.sender_wallet)

    def do_transfer_request(self):
        return self.client.post(
            '/transaction',
            headers=self.get_auth_headers(),
            json={
                'from': self.sender_wallet.address,
                'to': self.recipient_wallet.address,
                'amount': str(self.sent_amount),
            },
        )

    def check_transaction(self, initial_sender_wallet_value, initial_recipient_wallet_value, expected_status):
        self.refresh_from_db(self.sender_wallet)
        self.refresh_from_db(self.recipient_wallet)

        transaction = Transaction.query.first()
        self.assertIsNotNone(transaction)
        self.assertEqual(transaction.amount, self.sent_amount)
        self.assertEqual(transaction.status, expected_status)

        if expected_status == Transaction.STATUS_SUCCESS:
            self.assertEqual(self.sender_wallet.value, initial_sender_wallet_value - self.sent_amount)
            self.assertEqual(self.recipient_wallet.value, initial_recipient_wallet_value + self.sent_amount)
        elif expected_status == Transaction.STATUS_ERROR:
            self.assertEqual(self.sender_wallet.value, initial_sender_wallet_value)
            self.assertEqual(self.recipient_wallet.value, initial_recipient_wallet_value)

    def test_transfer_funds(self):
        initial_sender_wallet_value = self.sender_wallet.value
        initial_recipient_wallet_value = self.recipient_wallet.value

        response = self.do_transfer_request()
        self.assertEqual(response.status_code, 200)

        self.check_transaction(initial_sender_wallet_value, initial_recipient_wallet_value, Transaction.STATUS_SUCCESS)

    def test_insufficient_funds(self):
        self.sent_amount = self.sender_wallet.value + decimal.Decimal('0.01')

        initial_sender_wallet_value = self.sender_wallet.value
        initial_recipient_wallet_value = self.recipient_wallet.value

        response = self.do_transfer_request()
        self.assertEqual(response.status_code, 400)

        self.check_transaction(initial_sender_wallet_value, initial_recipient_wallet_value, Transaction.STATUS_ERROR)

    def test_wallet_limit(self):
        self.recipient_wallet.value = decimal.Decimal(self.client.application.config['MAX_WALLET_VALUE'])
        database.session.commit()
        self.refresh_from_db(self.recipient_wallet)

        initial_sender_wallet_value = self.sender_wallet.value
        initial_recipient_wallet_value = self.recipient_wallet.value

        response = self.do_transfer_request()
        self.assertEqual(response.status_code, 400)

        self.check_transaction(initial_sender_wallet_value, initial_recipient_wallet_value, Transaction.STATUS_ERROR)

    def test_wrong_wallet(self):
        foreign_username = 'fuser'
        foreign_password = 'fpassword'
        foreign_user = self.create_user(username=foreign_username, password=foreign_password)
        foreign_wallet = self.create_wallet(foreign_user)

        self.sender_wallet = foreign_wallet

        response = self.do_transfer_request()
        self.assertEqual(response.status_code, 400)

        transaction = Transaction.query.first()
        self.assertIsNone(transaction)


if __name__ == '__main__':
    unittest.main()
