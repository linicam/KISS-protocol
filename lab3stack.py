'''
Created on Sep 21, 2016

@author: sethjn
'''
import os
from Crypto.Cipher import AES
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Util import Counter

from playground.network.common.Protocol import StackingTransport, \
    StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING
from twisted.internet.protocol import Protocol, Factory

from lab3.lab2stackForLab3 import MyClientFactory, MyServerFactory


class KissHandShakeMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissHandShake"
    MESSAGE_VERSION = "1.0"

    BODY = [("key", STRING),
            ("IV", STRING)]


class KissDataMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissData"
    MESSAGE_VERSION = "1.0"

    BODY = [("data", STRING)]


class errType(object):
    GENERAL = "GENERAL"
    HANDSHAKE = "HANDSHAKE"
    TRANSMISSION = "TRANSMISSION"
    CHECK = "CHECK"
    TIMER = "TIMER"


class State(object):
    HANDSHAKE = "hankshake"
    ESTABLISHED = "established"


class KissTransport(StackingTransport):
    def __init__(self, lowerTransport, encrypter):
        StackingTransport.__init__(self, lowerTransport)
        self.__encrypter = encrypter

    def write(self, data):
        msg = KissDataMessage()
        msg.data = self.__encrypter.encrypt(data)
        self.lowerTransport().write(msg.__serialize__())


class KissProtocol(StackingProtocolMixin, Protocol):
    def __init__(self, isClient=False):
        self.__isClient = isClient
        self.__state = State.HANDSHAKE
        self.__storage = MessageStorage()
        self.__buffer = ""

    def buildHSEnAndDe(self):
        myPriKey = self.higherTransport.getHost().privateKey
        self.HSDecrypter = PKCS1OAEP_Cipher(myPriKey, None, None, None)

        peerPubKey = self.higherTransport.getPeer().certificateChain
        self.HSEncrypter = PKCS1OAEP_Cipher(peerPubKey, None, None, None)

    def setAesEncrypter(self):
        self.key = os.urandom(16).encode("hex")
        self.IV = os.urandom(8).encode("hex")
        IV_asCtr1 = Counter.new(128, initial_value=int(self.IV, 16))
        self.AESEncrypter = AES.new(self.key, counter=IV_asCtr1, mode=AES.MODE_CTR)

    def setAesDecrypter(self, msg):
        IV_asCtr2 = Counter.new(128, initial_value=int(self.HSDecrypter.decrypt(msg.IV), 16))
        self.AESDecrypter = AES.new(self.HSDecrypter.decrypt(msg.key), counter=IV_asCtr2, mode=AES.MODE_CTR)

    def connectionMade(self):
        log(errType.CHECK, 'KISS connection made')
        self.setAesEncrypter()
        self.higherTransport = KissTransport(self.transport, self.AESEncrypter)
        self.buildHSEnAndDe()
        if self.__isClient:
            self.sendHSPacket()

    def sendHSPacket(self):
        msg = KissHandShakeMessage()
        msg.key = self.HSEncrypter.encrypt(self.key)
        msg.IV = self.HSEncrypter.encrypt(self.IV)
        self.transport.write(msg.__serialize__())

    def recvHSPacket(self, msg):
        self.setAesDecrypter(msg)
        if not self.__isClient:
            self.sendHSPacket()

    def dataReceived(self, data):
        self.__buffer += data
        while self.__buffer:
            if self.__state == State.HANDSHAKE:
                msg, byte = KissHandShakeMessage.Deserialize(self.__buffer)
            else:
                msg, byte = KissDataMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            if self.__state == State.HANDSHAKE:
                self.recvHSPacket(msg)
                self.__state = State.ESTABLISHED
                self.makeHigherConnection(self.higherTransport)
                log(errType.CHECK, 'KISS established')
            elif self.__state == State.ESTABLISHED:
                self.processData(msg)

    def processData(self, msg):
        data = self.AESDecrypter.decrypt(msg.data)
        self.higherProtocol() and self.higherProtocol().dataReceived(data)


def log(type, msg):
    if type == errType.CHECK or type == errType.TIMER:
        print '\x1b[6;30;44m[' + type + ']: ' + msg + '\x1b[0m'
    else:
        print '\x1b[6;30;43m[' + type + ']: ' + msg + '\x1b[0m'


class KissClientFactory(StackingFactoryMixin, Factory):
    def buildProtocol(self, addr):
        return KissProtocol(True)


class KissServerFactory(StackingFactoryMixin, Factory):
    def buildProtocol(self, addr):
        return KissProtocol()


ConnectFactory = MyClientFactory.StackType(KissClientFactory)
ListenFactory = MyServerFactory.StackType(KissServerFactory)
