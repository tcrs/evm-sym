#!/usr/bin/env python3

import requests
import json

_base_url = 'https://mainnet.infura.io/'

def rpc(method, *params):
    payload = dict(
        jsonrpc = '2.0',
        method = method,
        params = params,
        id = 7)

    req = requests.post(
            _base_url, data=json.dumps(payload), headers={'content-type': 'application/json'})

    response = req.json()
    if response['id'] != 7 or response['jsonrpc'] != '2.0':
        raise RuntimeError(response)
    return response['result']

def _encblock(block):
    if block in {'latest', 'earliest', 'pending'}:
        return block
    else:
        return hex(block)

def code(addr, block='latest'):
    return rpc('eth_getCode', hex(addr), _encblock(block))

def balance(addr, block='latest'):
    return rpc('eth_getBalanceAt', hex(addr), _encblock(block))

def storage(addr, key, block='latest'):
    return rpc('eth_getStorageAt', hex(addr), hex(key), _encblock(block))

def block(block, full=True):
    return rpc('eth_getBlockByNumber', hex(block), full)

if __name__ == '__main__':
    import sys
    import argparse

    def block_parse(x):
        if x in {'latest', 'earliest', 'pending'}:
            return x
        else:
            return int(x, 0)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='op')
    code_parser = subparsers.add_parser('code', help='Get contract code')
    code_parser.add_argument('--block', default='latest', type=block_parse, help='Block number')
    code_parser.add_argument('address', type=lambda x: int(x, 0), help='Contract address')

    balance_parser = subparsers.add_parser('balance', help='Get contract balance')
    balance_parser.add_argument('--block', default='latest', type=block_parse, help='Block number')
    balance_parser.add_argument('address', type=lambda x: int(x, 0), help='Contract address')

    storage_parser = subparsers.add_parser('storage', help='Get contract storage')
    storage_parser.add_argument('--block', default='latest', type=block_parse, help='Block number')
    storage_parser.add_argument('address', type=lambda x: int(x, 0), help='Contract address')
    storage_parser.add_argument('key', type=lambda x: int(x, 0), help='Storage key')

    block_parser = subparsers.add_parser('block', help='Get block')
    block_parser.add_argument('--no-full', action='store_true', help='Only get transaction hashes')
    block_parser.add_argument('number', type=block_parse, help='Block number')

    args = parser.parse_args()
    if args.op == 'code':
        print(code(args.address, args.block))
    elif args.op == 'balance':
        print(balance(args.address, args.block))
    elif args.op == 'storage':
        print(storage(args.address, args.key, args.block))
    elif args.op == 'block':
        print(block(args.number, not args.no_full))
