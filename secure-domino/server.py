from deck_utils import *
import socket
import select
import sys
import queue
import pickle
from game import Game
import signal
import Colors
import time
from Crypto.Cipher import AES
from asym_keys import *
from ciphers import *
import player_pseudonyms as pp
pp.flush_game_data()

# Main socket code from https://docs.python.org/3/howto/sockets.html
# Select with sockets from https://steelkiwi.com/blog/working-tcp-sockets/

class TableManager:
        # Remove padding from status message
    def removePadding (self,msg):
        s=""
        for i in range(0,len(msg)):
            if (msg[i]!=0):
                s=s+chr (msg[i])
        return s

    # Creates a bytes with 16 bytes padding
    def pad16Bytes (self,msg):
        paddingChars=16-len(msg)%16
        paddedMsg=msg
        for i in range(paddingChars):
            paddedMsg=paddedMsg+b'\0'
        return paddedMsg

    # Creates a string with 16 bytes padding
    def pad16Str (self,msg):
        paddingChars=16-len(str (msg))%16
        paddedMsg=''.join(['\0' for i in range(paddingChars)])
        return str (msg)+paddedMsg

    # Receive client message
    def receiveMessageFromClient(self,client_socket):
        # receive message
        msg = client_socket.recv(8192)
        # get secret
        secret=self.public_keys[client_socket.getpeername()]
        # decrypt message
        iv = 16 * b'\0'
        aes = AES.new(secret[0], AES.MODE_CBC, iv)
        decd = aes.decrypt(msg)
        return decd

    # Send client message in bytes
    def sendMessageClient_Bytes(self,client_socket,msg):
        # get secret
        secret=self.public_keys[client_socket.getpeername()]
        # encrypt message and it needs to be a multiple of 16
        iv = 16 * b'\0'
        aes = AES.new(secret[0], AES.MODE_CBC, iv)
        encd = aes.encrypt(self.pad16Bytes(msg))
        try:
            client_socket.send(encd)
            return True
        except:
            return False

    # Send client message
    def sendMessageClient(self,client_socket,msg,secret):
        # encrypt message and it needs to be a multiple of 16
        iv = 16 * b'\0'
        aes = AES.new(secret, AES.MODE_CBC, iv)
        encd = aes.encrypt(bytes (self.pad16Str(msg),'utf-8'))
        try:
            client_socket.send(encd)
            return True
        except:
            return False

    # Establishing connection with client
    def establishingConnectionClient(self,server_socket):
        # client connect
        client_socket,addr = server_socket.accept()
        client_socket.setblocking(True)
        print('\n--------------------------------------------------------')
        print("Connecting with the cliente from ", addr)
        # negotiate keys with Diffie-Hellman algorithm
        g = 11
        p = 593
        random.seed()
        b = random.randint(10000, 999999)
        B = (g**b) % p
        client_socket.send(bytes(str(B), 'utf-8'))
        #chave cliente
        keyClient = client_socket.recv(8192).decode("utf-8")
        self.players_secrets.append(keyClient)
        print(self.players_secrets)
        secretServer = (int(keyClient)**b) % p

        # secret needs to have 16 characters
        secret=bytes (self.pad16Str(secretServer),'utf-8')

        # add entry to the list of secrets
        self.public_keys.update({client_socket.getpeername():(secret,"pseudonimo")})

        # send communication status to client
        if (self.sendMessageClient(client_socket, "Online",secret) == False):
            print("Error establishing communication")
            comStatus=""
        else:
            comStatus=self.receiveMessageFromClient(client_socket)
            comStatus=self.removePadding(comStatus)
            print('Status of client: ', comStatus)
        if (comStatus == "OK"):
            print ('\nConnection established!')
            print('--------------------------------------------------------\n')
            return client_socket,addr
        else:
            self.public_keys.popitem()
            return None


    def __init__(self, host, port, nplayers=4):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.setblocking(False)  # non-blocking for select
        self.server.bind((host, port))  # binding to localhost on 50000
        self.server.listen()
        self.game = Game(nplayers)  # the game associated to this table manager

        # Keys
        self.key_pair = {"private": ..., "public": ...}
        self.public_keys = {}  # Public keys of players: e.g.: {"P1":..., "P2":...}
        self.players_secrets = []
        #self.tiles_cipher = b''
        self.adjustPlayer = 1
        self.rcv_tiles_counter = 0
        self.rcv_deck_to_decrypt_counter = 0
        self.counter_to_start_play = 0
        self.nplayers = nplayers
        self.t_score = 0
        self.tiles_score = self.game.deck.total_score
        self.pieces_count = 0
        self.in_hand_scores = 0
        self.p_index = 3
        self.award_counter = 0
        self.cheating = 0
        print("Nplayers = ", nplayers)
        # disconnecting players when CTRL + C is pressed
        signal.signal(signal.SIGINT, self.signal_handler)
        # signal.pause()

        print("Server is On")

        # configuration for select()
        self.inputs = [self.server]  # sockets where we read
        self.outputs = []  # sockets where we write

        self.message_queue = {}  # queue of messages
        self.cli2cli_nick_source=""
        self.cli2cli_nick_dest=""

        while self.inputs:
            readable, writeable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            for sock in readable:
                if sock is self.server:  # this is our main socket and we are receiving a new client
                    connection, ip_address = self.establishingConnectionClient(sock)
                    print(Colors.BRed+"A new client connected -> " +
                          Colors.BGreen+"{}".format(ip_address)+Colors.Color_Off)
                    #connection.setblocking(False)
                    self.inputs.append(connection)  # add client to our input list
                    self.message_queue[connection] = queue.Queue()

                else:  # We are receiving data from a client socket
                    data=self.receiveMessageFromClient(sock)
                    if data:
                        to_send = self.handle_action(data, sock)
                        self.message_queue[sock].put(to_send)  # add our response to the queue
                        if sock not in self.outputs:
                            self.outputs.append(sock)  # add this socket to the writeable sockets
                    else:
                        if sock in self.outputs:
                            self.outputs.remove(sock)
                        self.inputs.remove(sock)
                        sock.close()
                        del self.message_queue[sock]

            for sock in writeable:
                try:
                    to_send = self.message_queue[sock].get_nowait()
                except queue.Empty:  # Nothing more to send to this client
                    self.outputs.remove(sock)
                else:
                    self.sendMessageClient_Bytes (sock,to_send)  # Send the info

            for sock in exceptional:  # if a socket is here, it has gone wrong and we must delete everything
                self.inputs.remove(sock)
                if sock in self.outputs:
                    self.outputs.remove(sock)
                sock.close()
                del self.message_queue[sock]

    def send_all(self, msg, socket=None):
        if socket is None:
            socket = self.server

        for sock in self.inputs:
            if sock is not self.server and sock is not socket:
                self.message_queue[sock].put(pickle.dumps(msg))
                if sock not in self.outputs:
                    self.outputs.append(sock)
        time.sleep(0.1)  # give server time to send all messages

    def send_host(self, msg):
        self.message_queue[self.game.host_sock].put(pickle.dumps(msg))
        if self.game.host_sock not in self.outputs:
            self.outputs.append(self.game.host_sock)

    def handle_action(self, data, sock):
        data = pickle.loads(data)
        action = data["action"]
        print("\n"+action)
        if data:
            if action == "hello":
                msg = {"action": "login", "msg": "Welcome to the server, what will be your name?"}
                return pickle.dumps(msg)
            # TODO login mechanic is flawed, only nickname
            if action == "req_login":
                print("User {} requests login, with nickname {}".format(
                    sock.getpeername(), data["msg"]))
                if not self.game.hasHost():  # There is no game for this tabla manager
                    self.game.addPlayer(data["msg"], sock,
                                        self.game.deck.pieces_per_player)  # Adding host
                    msg = {"action": "you_host", "msg": Colors.BRed +
                           "You are the host of the game"+Colors.Color_Off}
                    print("User "+Colors.BBlue +
                          "{}".format(data["msg"])+Colors.Color_Off+" has created a game, he is the first to join")
                    return pickle.dumps(msg)
                else:
                    if not self.game.hasPlayer(data["msg"]):
                        if self.game.isFull():
                            msg = {"action": "full", "msg": "This table is full"}
                            print("User {} tried to join a full game".format(data["msg"]))
                            return pickle.dumps(msg)
                        else:
                            self.game.addPlayer(
                                data["msg"], sock, self.game.deck.pieces_per_player)  # Adding player
                            msg = {"action": "new_player", "msg": "New Player "+Colors.BGreen+data["msg"]+Colors.Color_Off+" registered in game",
                                   "nplayers": self.game.nplayers, "game_players": self.game.max_players}
                            print("User "+Colors.BBlue +
                                  "{}".format(data["msg"])+Colors.Color_Off+" joined the game")

                            # send info to all players
                            self.send_all(msg)

                            # check if table is full
                            if self.game.isFull():
                                print(Colors.BIPurple+"The game is Full"+Colors.Color_Off)
                                msg = {"action": "waiting_for_host", "msg": Colors.BRed +
                                       "Waiting for host to start the game"+Colors.Color_Off}
                                self.send_all(msg, sock)
                            return pickle.dumps(msg)
                    else:
                        msg = {"action": "disconnect", "msg": "You are already in the game"}
                        print("User {} tried to join a game he was already in".format(data["msg"]))
                        return pickle.dumps(msg)

            if action == "start_cli2cli":
                self.cli2cli_nick_source=data["source"]
                self.cli2cli_nick_dest=data["dest"]
                msg={"action":"src_dh_cli2cli","msg":"Start sending to other client ("+self.cli2cli_nick_dest+"). I will relay."}
                return pickle.dumps(msg)

            if action == "dst_dh_cli2cli":
                # message from source to dest, lets send it
                msg={"action":"dst_dh_cli2cli","msg":data["msg"]}

                # enviar a mensagem da source para o destino e receber a resposta do destino
                for i in range (len(self.game.players)):
                    if self.game.players[i].name==self.cli2cli_nick_dest:
                        self.sendMessageClient_Bytes (self.game.players[i].socket,pickle.dumps(msg))
                        data1=self.receiveMessageFromClient (self.game.players[i].socket)
                        data2=pickle.loads(data1)
                        msg={"action":"src_dh2_cli2cli","msg":data2["msg"]}
                        break

                return pickle.dumps(msg)

            if action == "msg_to_dest_cli2cli":
                # Temos uma mensagem encriptada da source. Temos que a enviar para o destino
                msg={"action":"msg_from_src_cli2cli","msg":data["msg"]}

                # enviar a mensagem da source para o destino e receber a resposta do destino
                for i in range (len(self.game.players)):
                    if self.game.players[i].name==self.cli2cli_nick_dest:
                        self.sendMessageClient_Bytes (self.game.players[i].socket,pickle.dumps(msg))
                        break
                msg={"action":"wait","msg":"Client to client connection was closed. Waiting for next command."}
                return pickle.dumps(msg)

            if action=="close_cli2cli":
                print ("Client to client connection closed.")
                msg = {"action": "host_start_game", "msg": Colors.BYellow +
                       "The Host started the game"+Colors.Color_Off}
                self.send_all(msg, sock)
                return pickle.dumps(msg)

            if action == "get_nicks":
                nicks=[]
                for i in range (len(self.game.players)):
                    nicks.append(self.game.players[i].name)
                msg = {"action": "list_nicks", "msg": nicks, "skeys":self.players_secrets}
                self.send_all(msg, sock)
                return pickle.dumps(msg)

            if action == "start_game":
                msg ={"action":"cli2cli"}
                return pickle.dumps(msg)

            if action == "get_game_propreties":
                msg = {"action": "rcv_game_propreties"}
                msg.update(self.game.toJson())
                return pickle.dumps(msg)

            elif action == "game_ended":
                print(data["score"])
                if len(self.game.scores) == 3:
                    self.game.scores = []
                    self.pieces_count = 0
                self.game.scores.append(data["score"])
                self.pieces_count = self.pieces_count + data["number"]
                msg = {"action": "get_ready"}

            elif action == "send_scores":
                msg = {"action": "rcv_game_scores"}
                msg.update(self.game.toJson())
                self.send_all(msg, sock)

            if action == "choose_tiles":
                if self.adjustPlayer == 1:
                    self.game.previousPlayer()
                    self.adjustPlayer = 0

            if action == "start_the_play":
                self.counter_to_start_play += 1
                if self.counter_to_start_play == 3:
                    msg = {'action': 'rcv_game_propreties'}
                    self.game.next_action = "play"
                    msg.update(self.game.toJson())
                    self.send_all(msg, sock)
                else:
                    msg = {'action': 'wait', "msg":"Wait for everybody to be ready"}
                    self.send_all(msg, sock)

            if action == "disconnect":
                msg = {'action': 'disconnect'}
                self.send_all(msg, sock)


            player = self.game.currentPlayer()
            # check if the request is from a valid player
            if sock == player.socket:

                if action == "get_deck_to_encrypt":
                    if self.game.player_index == 0:
                        msg = {"action": "rcv_deck_to_encrypt"}
                        msg.update(self.game.toJson())
                        return pickle.dumps(msg)
                    elif self.game.player_index == 1 or self.game.player_index == 2:
                        msg = {"action": "rcv_cipher_to_encrypt", "cipher": self.game.encr}
                        return pickle.dumps(msg)

                elif action == "deck_encrypted":
                    self.game.encr = data["encrypted_deck"]
                    print(self.game.encr)
                    self.game.nextPlayer()
                    if self.game.player_index == 0 or self.game.player_index == 1:
                        msg = {"action": "wait", "msg": "Wait for all players to encrypt deck"}
                        return pickle.dumps(msg)
                    else:
                        msg = {"action": "host_start_game", "msg": "Encrypted Deck"}
                        self.send_all(msg,sock)

                if action == "choose_tiles":
                    self.game.nextPlayer()
                    msg = {"action": "rcv_game_propreties", "tiles":data["tiles"], "chosen":data["chosen"]}
                    msg.update(self.game.toJson())
                    self.send_all(msg, sock)

                if action == "receive_tiles":
                    self.rcv_tiles_counter += 1
                    print(self.rcv_tiles_counter)
                    if self.rcv_tiles_counter >= 4:
                        if self.game.player_index == 2:
                            msg = {"action": "rcv_game_propreties", "chosen": data["chosen"], 'keys': data['keys']}
                            self.game.next_action = "decrypt_deck"
                            if "refresh" in data:
                                for i in data["refresh"]:
                                    self.game.deck.aux_pseudonyms.remove(i)
                            msg.update(self.game.toJson())
                            self.send_all(msg, sock)
                        else:
                            msg = {"action": "wait", "msg": "Wait for all players to receive the tiles"}
                            self.send_all(msg, sock)
                    else:
                        self.game.nextPlayer()
                        msg = {"action": "rcv_game_propreties", "chosen": data["chosen"]}
                        if 'keys' in data:
                            # msg['keys'] = data['keys']
                            msg = {"action": "rcv_game_propreties", "chosen": data["chosen"], 'keys': data['keys']}
                        self.game.next_action = "create_tuple"
                        msg.update(self.game.toJson())
                        self.send_all(msg, sock)

                if action == "get_deck_to_decrypt":
                    self.rcv_deck_to_decrypt_counter += 1
                    if self.rcv_deck_to_decrypt_counter >= 3:
                        msg = {"action": "wait", "msg": "Wait for all players to decrypt deck"}
                        self.send_all(msg, sock)
                    else:
                        self.game.previousPlayer()
                        msg = {"action": "rcv_game_propreties", "chosen": data["chosen"], "keys": data["keys"], "counter": self.rcv_deck_to_decrypt_counter}
                        msg.update(self.game.toJson())
                        self.send_all(msg, sock)

                if action == "get_piece":
                    cipher_pieces = []
                    for i in range(len(data["chosen"])):
                        piece = self.game.deck.getPieceFromPseu(int(data["chosen"][i]))
                        pub_key = bytes_to_key(data["keys"][i])
                        valor_peca = str(piece.values[0].value)+str(piece.values[1].value)
                        peca_bytes = str.encode(valor_peca)
                        cipher_text = encrypt_rsa_hazmat(peca_bytes, pub_key)
                        cipher_pieces.append(cipher_text)
                        print(peca_bytes)
                    for i in range(len(data["chosen"])):
                        self.game.deck.removePiece(int(data["chosen"][i]))
                    print("deck -> " + ' '.join(map(str, self.game.deck.deck)))
                    msg = {"action": "rcv_piece", "cipher": cipher_pieces}
                    self.send_all(msg, sock)

                elif action == "start_the_play":
                    self.counter_to_start_play+=1
                    if self.counter_to_start_play == 3:
                        msg = {'action': 'rcv_game_propreties'}
                        self.game.next_action = "play"
                        msg.update(self.game.toJson())
                        self.send_all(msg, sock)

                    else:
                        msg = {'action': 'wait', "msg":"Wait for everybody to be ready"}
                        self.send_all(msg, sock)

                elif action == "play_piece":
                    next_p = self.game.nextPlayer()
                    if 'warning' in data:
                        print(Colors.BRed + "One of the players is protesting against cheating!" + Colors.Color_Off)
                        msg = {'action': 'disconnect'}
                        for sock in self.inputs:
                            if sock is not self.server:
                                self.sendMessageClient_Bytes (sock,pickle.dumps(msg))
                        print("Disconnecting Server ")
                        sys.exit(0)
                    if data["piece"] is not None:
                        player.nopiece = False
                        player.updatePieces(-1)

                        if len(self.game.deck.in_table) > 0:
                            if self.game.piece_in_ls(data["piece"], self.game.deck.in_table) or self.game.piece_in_ls(data["piece"], self.game.deck.deck):
                                print(Colors.BRed + "Invalid piece, play again!" + Colors.Color_Off)
                                print(self.game.next_action)
                                next_p = self.game.previousPlayer()
                                self.cheating = 1

                            else:
                                edges = []
                                edges.append(self.game.deck.in_table[0].values[0].value)
                                edges.append(self.game.deck.in_table[-1].values[1].value)
                                side_to_play1 = data["piece"].values[0].value
                                side_to_play2 = data["piece"].values[1].value
                                if side_to_play1 in edges or side_to_play2 in edges:
                                    print(Colors.BGreen + "Valid Play!!!" + Colors.Color_Off)
                                    print('Edges ' + ' '.join(edges))
                                    if data["edge"] == 0:
                                        self.game.deck.in_table.insert(0, data["piece"])
                                    else:
                                        self.game.deck.in_table.insert(
                                            len(self.game.deck.in_table), data["piece"])
                        else:
                            self.game.deck.in_table.insert(0, data["piece"])
                            print('First piece on the table!')

                    print("Player " + player.name+" played "+str(data["piece"]))
                    print("In table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")
                    print("Deck -> " + ''.join(map(str, self.game.deck.deck)) + "\n")
                    if data["win"]:
                        if player.checkifWin():
                            print(Colors.BGreen+" WINNER "+player.name+Colors.Color_Off)
                            msg = {"action": "end_game", "winner": player.name}
                    else:
                        if self.cheating == 1:
                            msg = {'action':'rcv_game_propreties','cheating' : 'true'}
                            self.cheating = 0
                        else:
                            msg = {"action": "rcv_game_propreties"}
                    msg.update(self.game.toJson())
                    self.send_all(msg, sock)

                elif action == "get_piece_from_pseu":
                    self.p_index = self.game.player_index
                    self.game.player_index = 2
                    if self.game.player_index == 2:
                        msg = {"action": "rcv_game_propreties", "chosen": data["piece"]}
                        self.game.next_action = "decrypt_tile"
                        self.game.deck.aux_pseudonyms.remove(int(data["piece"]))
                        msg.update(self.game.toJson())
                        self.send_all(msg, sock)
                    else:
                        msg = {"action": "wait", "msg": "acalma os cavalos"}
                        self.send_all(msg, sock)

                elif action == "decrypt_tile":
                    print(data["tile"])
                    self.game.previousPlayer()
                    msg = {"action": "rcv_game_propreties", "chosen": data["tile"],"second": "segundo"}
                    msg.update(self.game.toJson())
                    self.send_all(msg, sock)

                elif action == "tile_decrypted":
                    self.game.player_index = self.p_index
                    self.game.next_action = "play"
                    a = int(data["tile"])
                    print(self.game.deck.pseu_deck)
                    print(self.game.deck.aux_pseudonyms)
                    peca = self.game.deck.getPieceFromPseu(a)
                    self.game.deck.removePiece(a)

                    print(peca)
                    player.updatePieces(1)
                    msg = {'action': 'rcv_game_propreties', "piece":peca}
                    msg.update(self.game.toJson())
                    self.send_all(msg, sock)

                # no pieces to pick
                elif action == "pass_play":
                    self.game.nextPlayer()
                    # If the player passed the previous move
                    if player.nopiece:
                        msg = {"action": "end_game", "winner": Colors.BYellow+"TIE"+Colors.Color_Off}
                    # Update the variable nopiece so that the server can know if the player has passed the previous move
                    else:
                        print("No piece")
                        player.nopiece = True
                        msg = {"action": "rcv_game_propreties"}
                        msg.update(self.game.toJson())

                    self.send_all(msg, sock)
                    return pickle.dumps(msg)

                elif action == 'award':
                    self.award_counter += 1
                    if self.award_counter >= 4:
                        msg = {'action': 'disconnect'}
                        for sock in self.inputs:
                            if sock is not self.server:
                                self.sendMessageClient_Bytes (sock,pickle.dumps(msg))
                        print("Disconnecting Server ")
                        sys.exit(0)
                    else:
                        score = data['score']
                        biggest_score = 0
                        for l in self.game.scores:
                            if l > biggest_score:
                                biggest_score = l
                        print('NAME: ' + str(player.name))
                        points = biggest_score - score
                        print('Points: ' + str(points))
                        pp.award_points(player.name, int(points))
                        time.sleep(1.0)
                        self.game.nextPlayer()
                        msg = {"action": "award_points"}
                        self.send_all(msg, sock)

                elif action == 'game_over':
                    final_scores = data['score']
                    for fs in final_scores:
                        self.in_hand_scores = self.in_hand_scores + fs
                        print('Score: ' + str(fs))

                    print("In table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")
                    print("Deck -> " + ''.join(map(str, self.game.deck.deck)) + "\n")
                    for i in self.game.deck.in_table:
                        self.t_score = self.t_score + int(i.values[0].value) + int(i.values[1].value)
                    for k in self.game.deck.deck:
                        self.t_score = self.t_score + int(k.values[0].value) + int(k.values[1].value)
                    self.pieces_count = self.pieces_count + len(self.game.deck.in_table) + len(self.game.deck.deck)
                    # msg = {'action': 'game_over'}
                    # self.send_all(msg, sock)
                    if self.pieces_count != 28:
                        print(Colors.BRed + "Someone played 2 times in a row" + Colors.Color_Off)
                    else:
                        if self.in_hand_scores == (self.tiles_score-self.t_score):
                            print(Colors.BGreen + "GAME ACCOUNTING CORRECT" + Colors.Color_Off)
                            msg = {'action' : 'award_points'}
                            self.send_all(msg, sock)
                        else:
                            print(Colors.BRed + "Someone is cheating on their score or played a piece from deck!" + Colors.Color_Off)
                            msg = {'action': 'disconnect'}
                            for sock in self.inputs:
                                if sock is not self.server:
                                    self.sendMessageClient_Bytes (sock,pickle.dumps(msg))
                            print("Disconnecting Server ")
                            sys.exit(0)
                    time.sleep(1.0)
            else:
                msg = {"action": "wait", "msg": Colors.BRed+"Not Your Turn"+Colors.Color_Off}
            return pickle.dumps(msg)

    # Function to handle CTRL + C Command disconnecting all players
    def signal_handler(self, sig, frame):
        print('You pressed Ctrl+C!')
        size = len(self.inputs)-1
        msg = {"action": "disconnect", "msg": "The server disconnected you"}
        i = 1
        for sock in self.inputs:
            if sock is not self.server:
                print("Disconnecting player " + str(i) + "/" + str(size))
                self.sendMessageClient_Bytes (sock,pickle.dumps(msg))
                i += 1
        print("Disconnecting Server ")
        self.server.close()
        sys.exit(0)


try:
    NUM_PLAYERS = int(sys.argv[1])
except:
    NUM_PLAYERS = 3
a = TableManager('localhost', 50000, NUM_PLAYERS)
