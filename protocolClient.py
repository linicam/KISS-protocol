import sys

from myProtocol import lab2stack
from playground.twisted.endpoints import GateClientEndpoint
from twisted.internet import reactor, protocol, stdio
from twisted.protocols.basic import LineReceiver

from lab3 import lab3stack


class httpClient(protocol.Protocol):
    def connectionMade(self):
        print("Higher Connection Made")

    def dataReceived(self, data):
        print '<<<', data
        # sys.stdout.write('>>>')
        sys.stdout.flush()

    def sendMsg(self, data):
        print '>>>', data
        if data == "close":
            self.transport.loseConnection()
            return
        self.transport.write(data)

    def connectionLost(self, reason):
        print "[CLIENT] connection lost"
        # reactor.stop()


class httpClientFactory(protocol.ClientFactory):
    def __init__(self):
        pass

    global client

    def buildProtocol(self, addr):
        return client

    def clientConnectionFailed(self, connector, reason):
        print('Connection failed. Reason:', reason)
        reactor.stop()
        # ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        print('Lost connection.  Reason:', reason)
        reactor.stop()
        # ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


class stdIO(LineReceiver):
    global client
    delimiter = '\n'

    def connectionMade(self):
        self.transport.write('>>>>')

    def lineReceived(self, line):
        client.sendMsg(line)


global client
client = httpClient()
stdio.StandardIO(stdIO())
endpoint = GateClientEndpoint.CreateFromConfig(reactor, '20164.1.3414.2414', 19090, 'gatekey1',
                                               networkStack=lab3stack)
endpoint.connect(httpClientFactory())
reactor.run()
