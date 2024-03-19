"""
This module contains the Terms of Service Acceptor interface and its
related child implementations.
"""

import re


class Acceptor:  # pylint: disable=too-few-public-methods
    """
    The base Acceptor class defining the accept method interface
    """

    def accept(self, tos_uri):
        """Return true if the tos_uri is accepted by this Acceptor"""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement accept(tos_uri)"
        )


class AnyAcceptor(Acceptor):  # pylint: disable=too-few-public-methods
    """
    The Any Acceptor will return true for any tos_uri
    """

    def accept(self, tos_uri):
        return True


class RegexAcceptor(Acceptor):  # pylint: disable=too-few-public-methods
    """
    The Regex Acceptor will return true for any tos_uri that matches the
    configured regex pattern.
    """

    def __init__(self, regex):
        self.pattern = re.compile(regex)

    def accept(self, tos_uri):
        return bool(self.pattern.match(tos_uri))
