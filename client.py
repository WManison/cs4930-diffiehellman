#!/usr/bin/env python3
"""Stage 2: point your dh.py and mitm.py at the class server. You write the two functions marked YOUR TASK.

    A   an honest handshake: agree a secret with the server and read its message.
    B   Ava and Ben talk through you: read what Ava sends Ben.

The connection and the message format are written for you, the way wire.py
was. PROTOCOL.md lists every message and every field, in order.

    python3 client.py OURTEAM        both challenges
    python3 client.py OURTEAM A      one of them
"""

import json
import socket
import sys

import dh          # yours, from Step 1
import mitm        # yours, from Step 3
import wire        # given: the toy cipher Alice and Bob used

# The class server. --server host:port uses a different one for one run.
SERVER = ("66.42.112.186", 8930)


def solve_a(conn, team):
    """Challenge A: complete an honest handshake, then read what the server sends.

    Send "hello"; the server replies with the group and its public value, wants
    yours, then sends one encrypted message. Numbers travel as strings of
    digits and messages as hex (PROTOCOL.md). Return the plaintext.

    YOUR TASK.
    """

    # send the initial communication with the server
    conn.send({
        "msg": "hello",
        "challenge": "A",
        "team": team
    })

    # receive the server parameters
    params = conn.recv()

    # set the prime number and generator variables
    g = int(params["g"])
    p = int(params["p"])

    # receive the dictionary containing the server's public value
    public_value_dict = conn.recv()

    # set a variable for the server's public value
    server_public_value = int(public_value_dict["public"])

    # generate an own private key
    private_key = dh.generate_private(p)

    # generate the shared secret
    secret = dh.shared_secret(server_public_value, p, private_key)

    # generate the public_key
    public_key = dh.public_from(g, p, private_key)

    # send the public key to the server
    conn.send({
        "msg": "public",
        "public": str(public_key),
    })

    # recieve the encrypted dictionary that contains the flag
    encrypted_dict = conn.recv()

    # convert the hex value to a bytes object
    cypher = bytes.fromhex(encrypted_dict["blob"])
    print(cypher)

    # decrypt the cypher
    plain_text = wire.decrypt(secret, cypher)

    return plain_text


    #raise NotImplementedError("solve_a")


def solve_b(conn, team):
    """Challenge B: Ava and Ben send public values, then a message, through you.

    For every message the server hands you, send back what the other person
    should receive. The server checks that Ben can still read exactly what Ava
    wrote. Your Mallory from mitm.py does not change: turn each line of JSON
    into the wire.py Message she expects, and her answer back into JSON.

    Return the plaintext Ava sent to Ben.

    YOUR TASK.
    """

    # send the initial communication with the server
    conn.send({
        "msg": "hello",
        "challenge": "B",
        "team": team
    })

    # receive the server parameters
    params = conn.recv()

    # set the prime number and generator variables
    g = int(params["g"])
    p = int(params["p"])

    # create a Mallory object
    mallory = mitm.Mallory(g, p)

    # receive the dictionary containing Ava's public value
    public_value_dict = conn.recv()

    # set a public value variable
    received_public_value = int(public_value_dict["public"])

    # create a message object to send to Ben
    message_data = wire.Message("public", "Ava", "Ben", received_public_value)

    # swap the public values
    new_message = mallory.intercept(message_data)

    # send the intercepted message to the server
    conn.send({
        "msg": "public",
        "from": "Ava",
        "to": "Ben",
        "public": str(new_message.value)
    })

    # receive Ben's response
    ben_message = conn.recv()

    # set a public value variable
    received_public_value = int(ben_message["public"])

    # create a message object to send to Ava
    message_data = wire.Message("public", "Ben", "Ava", received_public_value)

    # swap the public values
    new_message = mallory.intercept(message_data)

    # send the intercepted message to the server
    conn.send({
        "msg": "public",
        "from": "Ben",
        "to": "Ava",
        "public": str(new_message.value)
    })

    # recieve the encrypted dictionary that contains Ava's message
    encrypted_dict = conn.recv()

    # convert the hex value to a bytes object
    cypher = bytes.fromhex(encrypted_dict["blob"])

    # create a message object for the message data
    message_data = wire.Message("text", "Ava", "Ben", cypher)

    # dcrypt and save the data, and then rencrypt it for Ben
    message_to_relay = mallory.intercept(message_data)

    # send the relayed message to Ben
    conn.send({
        "msg": "text",
        "from": "Ava",
        "to": "Ben",
        "blob": message_to_relay.value.hex()
    })

    # receive the result from the server
    flag_dict = conn.recv()

    #return the message in plaintext
    return mallory.read[-1][2]

    #raise NotImplementedError("solve_b")

# Everything below is given.

class ServerError(Exception):
    """The server refused something and said why."""


class Conn:
    """One connection, framed: a line of JSON out, a line of JSON in.

    TCP carries a stream of bytes with no message boundaries in it, so the two
    sides have to agree where one message ends. Here the rule is a newline, and
    socket.makefile turns the stream into something that can be read a line at
    a time.

        https://docs.python.org/3/library/socket.html
        https://docs.python.org/3/howto/sockets.html
    """

    def __init__(self, address, timeout=30):
        self.sock = socket.create_connection(address, timeout=timeout)
        self.stream = self.sock.makefile("rwb")

    def send(self, obj):
        """Send one dict as a line of JSON."""
        self.stream.write((json.dumps(obj) + "\n").encode())
        self.stream.flush()

    def recv(self):
        """The next line, as a dict. Raises ServerError if the server refused."""
        line = self.stream.readline()
        if not line:
            raise ServerError("the server closed the connection")
        obj = json.loads(line)
        if obj.get("msg") == "error":
            raise ServerError(obj.get("detail", "no reason given"))
        return obj

    def close(self):
        self.stream.close()
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def run(name, solve, address, team):
    print("== Challenge %s, team %s, server %s:%d ==" % (name, team, address[0], address[1]))
    try:
        with Conn(address) as conn:
            print("   recovered: %s" % solve(conn, team))
    except NotImplementedError as todo:
        print("   skipped: %s is not written yet" % todo)
    except ServerError as refused:
        print("   the server refused: %s" % refused)
    except OSError as broken:
        print("   could not talk to %s:%d (%s)." % (address[0], address[1], broken))
        print("   Is the address at the top of this file right, and is the server up?")
        print("   If the server is down, README.md, Stage 2, says what to do.")
    print()


USAGE = """usage: python3 client.py OURTEAM [A|B] [--server host:port]

  python3 client.py blue-3        both challenges
  python3 client.py blue-3 A      one of them"""


def main(argv):
    words = [a for a in argv[1:] if not a.startswith("--")]
    address = SERVER
    if "--server" in argv[1:-1]:
        host, _, port = argv[argv.index("--server") + 1].rpartition(":")
        address = (host, int(port))
        words = [w for w in words if w != "%s:%s" % (host, port)]
    if not words:
        print(USAGE)
        return 2

    team = words[0]
    which = words[1].upper() if len(words) > 1 else "AB"
    if "A" in which:
        run("A", solve_a, address, team)
    if "B" in which:
        run("B", solve_b, address, team)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
