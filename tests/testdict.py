import json
class TestDict(dict):
    """ A dictionary where each key is hashed and each value is encrypted.

    """

    def __init__(self, *args, **kwargs):
        """ Initialize the dictionary.

        """

        super(TestDict, self).__init__(*args, **kwargs)

    def __getitem__(self, key: bytes) -> bytes:
        """ Returns the decrypted value associated with key.

        """

        print('__getitem__', key)
        t = json.loads(super(TestDict, self).__getitem__(key))
        print('__getitem__', t)
        return t

    def __setitem__(self, key: bytes, value: bytes) -> bytes:
        """ Set data.

        """

        print('__setitem__', key, value)
        super(TestDict, self).__setitem__(key, json.dumps(value))

    def __setattr__(self, a, b):
        print("__setattr__", a, b)
        super(TestDict, self).__setattr__(a, b)

    def __getattribute__(self, a):
        print("__getattribute__", a)
        super(TestDict, self).__getattribute__(a)

    def __getattr__(self, a):
        print("__getattr__", a)
        super(TestDict, self).__getattr__(a)

    def update(self, a):
        print('update', a)
        super(TestDict, self).update(a)
