__all__ = (
    'User',
    'Wallet',
    'Transaction',
    'init_app',
    'db',
)

import decimal
import uuid

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import generate_password_hash

from config import MAX_WALLET_VALUE
from errors import AlreadyExist, NonEmptyWallet, InsufficientFunds, WalletLimit, TransactionError

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)

    @classmethod
    def create(cls, username: str, password: str):
        user = cls(username=username, password=generate_password_hash(password))
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            raise AlreadyExist('User already exist')

        db.app.logger.info('Created new user: {}'.format(username))
        return user


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(32), unique=True, nullable=False, index=True)
    value = db.Column(db.Numeric(scale=2), nullable=False, default=0.0)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('wallets', lazy='dynamic'))

    @classmethod
    def create(cls, user: User):
        wallet = cls(address=uuid.uuid4().hex, user=user)
        db.session.add(wallet)
        db.session.commit()
        db.app.logger.info('Created new wallet: {} by user {}'.format(wallet.address, user.username))
        return wallet

    def delete(self):
        if not self.value.is_zero():
            raise NonEmptyWallet('Сan not delete a non-empty wallet.')

        db.session.delete(self)
        db.session.commit()
        db.app.logger.info('Deleted wallet: {}'.format(self.address))

    def add_funds(self, amount: decimal.Decimal):
        if self.value >= decimal.Decimal(db.app.config['MAX_WALLET_VALUE']):
            raise WalletLimit('Wallet reached the limit')

        self.value += amount

    def withdraw_funds(self, amount: decimal.Decimal):
        if self.value < amount:
            raise InsufficientFunds

        self.value -= amount


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    recipient = db.relationship(
        'Wallet', backref=db.backref('received_transactions', lazy=True), foreign_keys=[recipient_id],
    )

    sender_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    sender = db.relationship(
        'Wallet', backref=db.backref('sent_transactions', lazy=True), foreign_keys=[sender_id],
    )

    amount = db.Column(db.Numeric(scale=2), nullable=False, default=0.0)
    status = db.Column(db.String())

    STATUS_PENDING = 'pending'
    STATUS_SUCCESS = 'success'
    STATUS_ERROR = 'error'

    @classmethod
    def create(cls, recipient: Wallet, sender: Wallet, amount: decimal.Decimal):
        transaction = cls(recipient=recipient, sender=sender, amount=amount, status=cls.STATUS_PENDING)
        db.session.add(transaction)
        db.session.commit()
        db.app.logger.info(
            'User {} transfer funds from {} to {}'.format(sender.user.username, sender.address, recipient.address),
        )
        return transaction

    def process_error(self):
        db.session.rollback()
        self.status = self.STATUS_ERROR
        db.session.commit()

    def process(self):
        try:
            self.sender.withdraw_funds(self.amount)
            self.recipient.add_funds(self.amount)
            self.status = self.STATUS_SUCCESS

            db.session.commit()

        except (InsufficientFunds, WalletLimit):
            self.process_error()
            raise

        except SQLAlchemyError:
            self.process_error()
            raise TransactionError


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db.app = app
        db.init_app(app)
        db.create_all()


def close_db(exception=None):
    if exception:
        db.app.logger.error('Captured exception while closing db: {}'.format(exception))
    db.session.remove()
