import mox
import socket
import unittest

from pybitcoin import io


class TestIOLoop(unittest.TestCase):
    def test_ioloop(self):
        io


class TestRecvBytes(mox.MoxTestBase):
    def test_recv_bytes_empty(self):
        self.assertEqual(io.recv_bytes(None, 0), '')

    def test_recv_bytes_1(self):
        sock = self.mox.CreateMock(socket.socket)
        self.mox.StubOutWithMock(sock, 'recv')
        sock.recv(1).AndReturn('a')
        self.mox.ReplayAll()
        self.assertEqual(io.recv_bytes(sock, 1), 'a')

    def test_recv_bytes_2(self):
        sock = self.mox.CreateMock(socket.socket)
        self.mox.StubOutWithMock(sock, 'recv')
        sock.recv(2).AndReturn('ab')
        self.mox.ReplayAll()
        self.assertEqual(io.recv_bytes(sock, 2), 'ab')

    def test_recv_bytes_2_split(self):
        sock = self.mox.CreateMock(socket.socket)
        self.mox.StubOutWithMock(sock, 'recv')
        sock.recv(1).AndReturn('a')
        sock.recv(1).AndReturn('b')
        self.mox.ReplayAll()
        self.assertEqual(io.recv_bytes(sock, 1), 'ab')
