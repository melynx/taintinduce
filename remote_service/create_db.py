from sqlalchemy import create_engine
from sqlalchemy import Column, ForeignKey, Integer, String, Binary, LargeBinary
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    password = Column(Binary(), nullable=False)

class Instruction(Base):
    __tablename__  = 'instructions'
    bytestring = Column(String(255), primary_key=True)
    state_format = Column(String(255), nullable=False)

class Observation(Base):
    __tablename__ = 'observations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    insn_bytestring = Column(String(255), nullable=False)
    serialize_blob = Column(LargeBinary(), nullable=False)

class Rule(Base):
    __tablename__ = 'rules'
    insn_bytestring = Column(String(255), primary_key=True)
    serialize_blob = Column(LargeBinary(), nullable=False)

def main():
    engine = create_engine('sqlite:///database.db')
    Base.metadata.create_all(engine)

if __name__ == "__main__":
    main()
