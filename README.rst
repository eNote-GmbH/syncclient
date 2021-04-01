Python Firefox Sync client
##########################


This is a python client for Firefox Sync. Check it out with::

  $ pip install -e .
  $ python syncclient/main.py --help

For instance, if you want to get all passwords (encrypted) use the
`get_records` action:

.. code-block::

  $ python syncclient/main.py -c test_client -u alexis@notmyidea.org get_records passwords
  [u'{1c1e0eea-d9c2-4c59-b95e-4dbe0800639f}',
   u'{0a76ec08-ba7c-48b1-b026-1d65085f789e}',
   u'{7482b391-bf2f-4542-8ebd-27c4398487ff}',
   u'{37bc9298-ac49-c54e-a73d-d817434ed0b2}',
   u'{d5ff4718-d4a0-4703-b0af-7d1c79c3a099}']
