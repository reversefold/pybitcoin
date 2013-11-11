from sqlalchemy import create_engine
from sqlalchemy import BINARY

engine = create_engine('sqlite:///pybitcoin.sqlite')  #, echo=True)
