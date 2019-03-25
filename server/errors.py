class AlreadyExist(Exception):
    pass


class NonEmptyWallet(Exception):
    pass


class TransactionError(Exception):
    pass


class InsufficientFunds(TransactionError):
    pass


class WalletLimit(TransactionError):
    pass
