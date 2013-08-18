#from pybitcoin import protocol
#from tables import open_file, IsDescription, StringCol, UInt32Col, UInt64Col, VLStringAtom
#
#
#h5file = open_file('pybitcoin.h5', mode='w', title='PyBitcoin')
#table_group = h5file.create_group('/', 'tables', 'PyBitcoin')
#va_group = h5file.create_group('/', 'varstrs', 'Variable length strings')
#
#
#class TxInDescriptor(IsDescription):
#    previous_output_transaction_hash = StringCol(32)
#    previous_output_index = UInt32Col()
#    #signature_script = VLStringAtom()
#    signature_script_index = UInt32Col()
#    sequence = UInt32Col()
#
#
#class TxIn(protocol.TxIn):
#    TABLE = h5file.create_table(table_group, 'txin', TxInDescriptor, 'TxIn')
#    SIGSCRIPT = h5file.create_vlarray(va_group, 'txin_sigscript', VLStringAtom(), 'TxIn signature_script')
#
#
#class TxOutDescriptor(IsDescription):
#    value = UInt64Col()
#    pk_script_index = UInt32Col()
