Python Firefox Sync client
##########################


This is a python client for Firefox Sync. Check it out with::

  $ pip install -e .
  $ python syncclient/main.py --help

To pull data from a sync server, you will need a client id::

  $ fxa-client -v -u me@example.com --account-server https://api.accounts.firefox.com/v1 --oauth-server https://oauth.accounts.firefox.com/v1 --bearer
  # ---- BEARER TOKEN INFO ----
  # User: me@example.com
  # Scopes: profile
  # Account: https://api.accounts.firefox.com/v1
  # Oauth: https://oauth.accounts.firefox.com/v1
  # Client ID: <YOUR CLIENT ID>
  # ---------------------------

For instance, if you want to get all passwords (encrypted) use the
`get_records` action::

  $ python syncclient/main.py -u "me@example.com" --client-id <YOUR CLIENT ID> get_records password
  [u'{1c1e0eea-d9c2-4c59-b95e-4dbe0800639f}',
   u'{0a76ec08-ba7c-48b1-b026-1d65085f789e}',
   u'{7482b391-bf2f-4542-8ebd-27c4398487ff}',
   u'{37bc9298-ac49-c54e-a73d-d817434ed0b2}',
   u'{d5ff4718-d4a0-4703-b0af-7d1c79c3a099}']

If you want to get all bookmarks (decrypted)::

  $ python syncclient/main.py -u "me@example.com" --client-id <YOUR CLIENT ID> get_records bookmarks

To point to a different syncserver::

  TOKENSERVER_URL="https://example.com/token" python3 syncclient/main.py -u "me@example.com" --decrypt --client-id <YOUR CLIENT ID> get_records history | jq | less -S
