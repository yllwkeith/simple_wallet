import cmd
import sys

import requests
from requests import HTTPError

DEFAULT_SERVER_URL = 'http://127.0.0.1:5000'


class SimpleWalletCLI(cmd.Cmd):
    intro = 'Simple wallet CLI.   Type help or ? to list commands.\n'
    prompt = '(simple wallet)'

    USER_URI = '/user'
    WALLETS_URI = '/wallets'
    TRANSACTION_URI = '/transaction'

    def __init__(self, *args, **kwargs):
        self.username = None
        self.password = None
        self.base_url = kwargs.pop('url')

        super().__init__(*args, **kwargs)

    def do_login(self, arg):
        """Args: username, password. Login into simple wallet."""

        try:
            username, password = arg.split()
        except ValueError:
            print('Please specify username and password')
            return

        with requests.get('{}{}'.format(self.base_url, self.WALLETS_URI), auth=(username, password)) as response:
            if response.status_code == 401:
                print('Wrong credentials')
                return
            print('Successfully logged in')
            self.prompt = '({})'.format(username)
            self.username = username
            self.password = password

    def do_logout(self, arg):
        """Logout"""
        self.prompt = '(simple wallet)'
        self.username = None
        self.password = None

    def do_registration(self, args):
        """Args: username, password. Register new account."""
        try:
            username, password = args.split()
        except ValueError:
            print('Please specify username and password')
            return

        with requests.post(
                '{}{}'.format(self.base_url, self.USER_URI), json={'username': username, 'password': password}
        ) as response:
            response.raise_for_status()
            print('[#] {}'.format(response.json()['message']))

            self.prompt = '({})'.format(username)
            self.username = username
            self.password = password

    def do_create_wallet(self, args):
        """Create new wallet"""
        with requests.post(
                '{}{}'.format(self.base_url, self.WALLETS_URI), auth=(self.username, self.password)
        ) as response:
            response.raise_for_status()
            print('Created new wallet with address: {}'.format(response.json()['address']))

    def do_show_wallets(self, address):
        """Args: address(optional). Show wallets info."""
        if address:
            url = '{}{}/{}'.format(self.base_url, self.WALLETS_URI, address)
        else:
            url = '{}{}'.format(self.base_url, self.WALLETS_URI)
        with requests.get(url, auth=(self.username, self.password)) as response:
            response.raise_for_status()
            json = response.json()
            wallets = json.get('wallets', [json])

            if not wallets:
                print('You have no wallets')

            for wallet in wallets:
                address = wallet['address']
                value = wallet['value']
                print('[#] Address: {} value: {}'.format(address, value))

    def do_delete_wallet(self, address):
        """Args: address. Delete wallet with specific address."""
        if not address:
            print('Please specify address')
            return

        with requests.delete(
                '{}{}/{}'.format(self.base_url, self.WALLETS_URI, address), auth=(self.username, self.password),
        ) as response:
            response.raise_for_status()
            print('[#] Wallet deleted')

    def do_transfer_funds(self, args):
        """Args: from_wallet, to_wallet, amount. Transfer funds from one wallet to another."""
        try:
            from_wallet, to_wallet, amount = args.split()
        except ValueError:
            print('Please specify from_wallet, to_wallet, amount')
            return

        with requests.post(
                '{}{}'.format(self.base_url, self.TRANSACTION_URI), auth=(self.username, self.password),
                json={'from': from_wallet, 'to': to_wallet, 'amount': amount},
        ) as response:
            response.raise_for_status()
            print(response.json()['message'])

    def onecmd(self, line):
        try:
            super().onecmd(line)
        except requests.exceptions.ConnectionError:
            print('Server refuses connection')
        except HTTPError as e:
            error = 'Unknown'
            if e.response.status_code in [400, 401, 409]:
                error = e.response.json()['error']
            print('[!]Error: {}'.format(error))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        url = sys.argv[1]
    else:
        url = DEFAULT_SERVER_URL

    SimpleWalletCLI(url=url).cmdloop()
