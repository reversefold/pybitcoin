from sqlalchemy import create_engine
from sqlalchemy import BINARY


def engine_factory():
    return create_engine('sqlite:///pybitcoin.sqlite')  # , echo=True)

__all__ = ('BINARY', 'engine_factory')
