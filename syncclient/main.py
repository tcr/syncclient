import argparse
import json
from client import SyncClient, get_browserid_assertion, get_encryption_key, decrypt_data
from pprint import pprint


def main():
    parser = argparse.ArgumentParser(
        description="""CLI to interact with Firefox Sync""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(dest='login',
                        help='Firefox Accounts login.')
    parser.add_argument(dest='password',
                        help='Firefox Accounts password.')
    parser.add_argument(dest='action', help='The action to be executed',
                        default='info_collections', nargs='?',
                        choices=[m for m in dir(SyncClient)
                                 if not m.startswith('_')])

    args, extra = parser.parse_known_args()
    # for decrypt data, need FxA->KeyB
    bid_assertion_args = get_browserid_assertion(args.login, args.password)
    client = SyncClient(*bid_assertion_args)
    encryption_key = get_encryption_key(client, args.login, args.password)

    result = getattr(client, args.action)(*extra)
    if isinstance(result, list):
        for item in result:
            item['payload'] = json.dumps(decrypt_data(encryption_key, item['payload']))
    pprint(result)

if __name__ == '__main__':
    main()
