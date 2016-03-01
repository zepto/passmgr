class TestDict(dict):
    """ A dictionary where each key is hashed and each value is encrypted.

    """

    def __init__(self, data_dict: dict = {}):
        """ Initialize the dictionary.

        """

        super(TestDict, self).__init__(data_dict)

    def __getitem__(self, key: bytes) -> bytes:
        """ Returns the decrypted value associated with key.

        """

        return self.__dict__.__getitem__(key)

    def __setitem__(self, key: bytes, value: bytes) -> bytes:
        """ Set data.

        """

        self.__dict__.__setitem__(key, b'testdict %s' % value)

