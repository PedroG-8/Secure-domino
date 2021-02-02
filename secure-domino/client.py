import socket
import sys
import pickle
import Colors
import string
from deck_utils import Player, Piece
import random
from Crypto.Cipher import AES
from asym_keys import *
from ciphers import *
import player_pseudonyms as pp
#from cryptography.hazmat.primitives import serialization

#lambda function to remove elements from list taken from:
#https://stackoverflow.com/questions/1157106/remove-all-occurrences-of-a-value-from-a-list

secret=''

class client():
    # Returns string without 16 bytes padding
    def removePaddingStr (self,msg):
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



    def __init__(self, host, port):
        self.game_over_flag = 0
        self.deck_encrypted=False
        global secret
        print('\n--------------------------------------------------------')
        print("Connecting with the server ...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((host, port))
        # negotiate keys with Diffie-Hellman algorithm
        g = 11
        p = 593
        #random.seed()
        a = random.randint(10000, 999999)
        A = (g**a) % p
        self.key_p = p
        self.key_a = a
        self.key_AA = str(A)
        print('My Public Key: ' + str(A))
        self.sock.send(bytes(str(A), 'utf-8'))
        #chave servidor
        keyServer = self.sock.recv(8192).decode("utf-8")
        secretClient = (int(keyServer)**a) % p
        print('Shared secret: %s' % secretClient)

        # secret needs to have 16 characters
        secret=bytes (self.pad16Str(str (secretClient)),'utf-8')

        # recieve communication status from manager
        comStatus=self.sock.recv(8192)
        iv = 16 * b'\0'
        aes = AES.new(secret, AES.MODE_CBC, iv)
        data = aes.decrypt(comStatus)
        data=self.removePaddingStr(data)
        print ('Status of manager: %s' % data)

        # if manager responds with "Online", the client send "OK"
        if (data == "Online"):
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            data1=aes.encrypt(bytes (self.pad16Str("OK"),'utf-8'))
            self.sock.send(data1)
            print ('\nConnection established!')
            print('--------------------------------------------------------\n')

        else:
            print ('Error establishing connection')

        first_msg = {"action": "hello"}
        self.sendData(pickle.dumps(first_msg))
        self.player = None
        self.players_nicks = []
        self.cli2cli_secret_src=""
        self.cli2cli_secret_dest=""
        self.cli2cli_a_src=0
        self.cli2cli_a_dst=0
        self.receiveData()


    # Send manager message
    def sendData(self,msg):
        global secret
        # encrypton with AES and the message needs to be a multiple of 16
        iv = 16 * b'\0'
        aes = AES.new(secret, AES.MODE_CBC, iv)
        encd = aes.encrypt(self.pad16Bytes(msg))
        try:
            self.sock.send(encd)
            return True
        except:
            return False

    def sendDataPlayer(self,msg,player_secret):
        psecret = bytes (self.pad16Str(str (player_secret)),'utf-8')
        # encrypton with AES and the message needs to be a multiple of 16
        new_msg = bytes(msg)
        iv = 16 * b'\0'
        aes = AES.new(psecret, AES.MODE_CBC, iv)
        encd = aes.encrypt(self.pad16Bytes(new_msg))
        return encd

    # Send manager message
    def sendListData(self,msg,player_secret):
        psecret = bytes (self.pad16Str(str (player_secret)),'utf-8')
        # encrypton with AES and the message needs to be a multiple of 16
        iv = 16 * b'\0'
        aes = AES.new(psecret, AES.MODE_CBC, iv)
        encd = aes.encrypt(self.pad16Bytes(msg))
        return encd


    def receiveData(self):
        global secret

        while True:
            msg = self.sock.recv(8192)
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            data = aes.decrypt(msg)
            if data:
                self.handle_data(data)

    def receiveDataPlayer(self, player_data, player_secret):
        psecret = bytes (self.pad16Str(str (player_secret)),'utf-8')
        while True:
            iv = 16 * b'\0'
            aes = AES.new(psecret, AES.MODE_CBC, iv)
            new_data = aes.decrypt(player_data)
            list_data = list(bytes(new_data))
            return list_data

    def receive_data_cena_fixe(self, player_data, player_secret):
        psecret = bytes (self.pad16Str(str (player_secret)),'utf-8')
        while True:
            iv = 16 * b'\0'
            aes = AES.new(psecret, AES.MODE_CBC, iv)
            new_data = aes.decrypt(player_data)
            new_data = new_data.replace(b'\x00', b'')
            return new_data

    def handle_data(self, data):
        data = pickle.loads(data)
        action = data["action"]
        print("\n"+action)
        if action == "login":
            nickname = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) #input(data["msg"])
            print("Your name is "+Colors.BBlue+nickname+Colors.Color_Off)
            msg = {"action": "req_login", "msg": nickname}#, "p_key": pem}
            self.player = Player(nickname,self.sock)
            pp.add_pl ayer(nickname)
            self.sendData(pickle.dumps(msg))
            return
            # todo login
        elif action == "you_host":
            self.player.host=True
        elif action == "new_player":
            print(data["msg"])
            print("There are "+str(data["nplayers"])+"\\"+str(data["game_players"]))

        elif action == "waiting_for_host":
            if self.player.host:
                msg={"action":"get_nicks"}
                self.sendData(pickle.dumps(msg))
                print("Sent ", msg)
            else:
                print(data["msg"])

        elif action == "host_start_game":
            print(data["msg"])
            if not self.player.host:
                self.player.wait_value = 1
            if not self.deck_encrypted:
                msg = {"action": "get_deck_to_encrypt"}
                self.deck_encrypted = True
            else:
                msg = {"action": "get_game_propreties"}
                self.deck_encrypted = True
            self.sendData(pickle.dumps(msg))
            print("Sent ", msg)

        elif action == "list_nicks":
            print(data["msg"])
            for i in range (len(data["msg"])):
                if data["msg"][i]!=self.player.name:
                    self.players_nicks.append(data["msg"][i])
            self.players_secrets = data["skeys"]
            self.shared_secrets = []
            self.next_player_key = 0
            self.previous_player_key = 0
            i=0
            j=3
            l=3
            for k in self.players_secrets:
                if k == self.key_AA:
                    self.shared_secrets.append(0)
                    j=i+1
                    l=i-1
                else:
                    self.shared_secrets.append((int(k)**self.key_a) % self.key_p)
                i+=1
            if j == 3:
                j=0
            if l == -1:
                l=2
            self.next_player_key = self.shared_secrets[j]
            self.previous_player_key = self.shared_secrets[l]
            print('Clients Public Keys: ' + str(self.players_secrets))
            print('Clients shared Secrets: ' + str(self.shared_secrets))

            if self.player.host:
                input(Colors.BGreen+"PRESS ENTER TO START THE GAME"+Colors.Color_Off)
                msg = {"action": "start_game"}
                self.sendData(pickle.dumps(msg))

        # Cifragem do BARALHO
        elif action == "rcv_deck_to_encrypt":
            self.player.nplayers = data["nplayers"]
            self.player.npieces = data ["npieces"]
            self.player.pieces_per_player = data["pieces_per_player"]
            self.player.in_table = data["in_table"]
            self.player.deck = data["deck"]
            self.player.wait_value = 0
            print("Deck received -----")
            print(self.player.deck)

            # Cifragem HOST
            enc = self.player.encrypt_deck_host(self.player.deck)
            msg = {"action": "deck_encrypted", "encrypted_deck": enc}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_cipher_to_encrypt":
            self.player.deck = data["cipher"]
            self.player.wait_value = 0

            # Cifragem NÃO HOST
            enc = self.player.encrypt_deck_player(self.player.deck)
            msg = {"action": "deck_encrypted", "encrypted_deck": enc}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_piece":
            peca_aux = ""
            for l in data["cipher"]:
                for k in self.player.priv_keys:
                    peca = decrypt_rsa_hazmat(cipher_text=l, priv_key=k)
                    if len(peca) == 2:
                        peca_aux=str(peca, 'utf-8')
                        subpiece_1=peca_aux[0]
                        subpiece_2=peca_aux[1]
                        piece=Piece(subpiece_1, subpiece_2)
                        self.player.hand.append(piece)
                        break
            print("Pieces in my hand -> " + ' '.join(map(str, self.player.hand)))

            msg = {"action": "start_the_play"}
            self.sendData(pickle.dumps(msg))


        elif action == "rcv_game_propreties":
            self.player.nplayers = data["nplayers"]
            self.player.npieces = data ["npieces"]
            self.player.pieces_per_player = data["pieces_per_player"]
            self.player.in_table = data["in_table"]
            self.player.deck = data["pseu_deck"]
            player_name = data["next_player"]
            print('----------------------------------------------------------------------')

            if data["next_player"] == self.player.name:
                player_name = Colors.BGreen + "YOU" + Colors.Color_Off
            print(Colors.BBlue + "Current player -> " + Colors.Color_Off + player_name)
            print("Next Action ->", data["next_action"])
            print("Deck -> " + ' '.join(map(str, self.player.deck)) + "\n")
            print("Hand -> " + ' '.join(map(str, self.player.hand)))
            print("In table -> " + ' '.join(map(str, data["in_table"])) + "\n")
            if self.player.name == data["next_player"]:
                if data["next_action"] == "choose_tiles":
                    self.player.wait_value = 0
                    if not self.player.ready_to_play:
                        if "tiles" in data:
                            tiles_able_to_choose = self.receiveDataPlayer(data["tiles"], self.previous_player_key)
                            tiles_chosen = self.receiveDataPlayer(data["chosen"], self.previous_player_key)
                            tiles_able_to_choose = list(filter(lambda a: a != 0, tiles_able_to_choose))
                            tiles_chosen = list(filter(lambda a: a != 0, tiles_chosen))
                            print('Pseudonyms able to choose: ' + str(tiles_able_to_choose))
                            print('Pseudonyms chosen: ' + str(tiles_chosen))
                            print(tiles_chosen)
                            # Alterar para randint(1,2) se estiver muito lento
                            prob = random.randint(1, 20)
                            pass
                            if prob == 1 and len(self.player.picked_pieces) < 5:
                                print('Pick tile')
                                random.shuffle(tiles_able_to_choose)
                                piece = tiles_able_to_choose.pop()
                                print("Picked piece: " + str(piece))
                                tiles_chosen.append(piece)
                                self.player.picked_pieces.append(piece)
                                tiles_able_to_choose.sort()
                                cipher_tiles = self.sendDataPlayer(tiles_able_to_choose,self.next_player_key)
                                cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)
                                msg = {"action": "choose_tiles", "tiles": cipher_tiles, "chosen": cipher_chosen}
                            elif prob == 2 and len(self.player.picked_pieces) > 0:
                                print('Swap tile')
                                random.shuffle(tiles_able_to_choose)
                                chosen_piece = tiles_able_to_choose.pop()
                                replace_piece = self.player.picked_pieces.pop()
                                tiles_chosen.append(chosen_piece)
                                tiles_chosen.remove(replace_piece)
                                tiles_able_to_choose.append(replace_piece)
                                self.player.picked_pieces.append(chosen_piece)
                                ### Comentar as 8 linhas acima e descomentar
                                # as seguintes para que cada jogador troque
                                # várias peças ao mesmo tempo, funciona a maior parte das vezes
                                # mas quando falha encrava o jogo
                                #
                                # print('Swap tile')
                                # random.shuffle(tiles_able_to_choose)
                                # rand_replaces = random.randint(1, len(self.player.picked_pieces))
                                # print(rand_replaces)
                                # chosen_pieces = []
                                # replace_pieces = []
                                # for i in range(0, rand_replaces):
                                #     chosen_pieces.append(tiles_able_to_choose.pop())
                                #     replace_pieces.append(self.player.picked_pieces.pop())
                                # for i in chosen_pieces:
                                #     tiles_chosen.append(i)
                                #     self.player.picked_pieces.append(i)
                                # for i in replace_pieces:
                                #     tiles_chosen.remove(i)
                                #     tiles_able_to_choose.append(i)
                                ###
                                tiles_able_to_choose.sort()
                                cipher_tiles = self.sendDataPlayer(tiles_able_to_choose,self.next_player_key)
                                cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)
                                msg = {"action": "choose_tiles", "tiles": cipher_tiles, "chosen": cipher_chosen}
                            else:
                                print('Pass')
                                cipher_tiles = self.sendDataPlayer(tiles_able_to_choose,self.next_player_key)
                                cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)

                                msg = {"action": "choose_tiles", "tiles": cipher_tiles, "chosen": cipher_chosen}
                                if(len(tiles_chosen)==15):
                                    cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)
                                    msg={"action": "receive_tiles", "chosen": cipher_chosen}
                            print(self.player.picked_pieces)
                            self.sendData(pickle.dumps(msg))
                        else:
                            self.player.deck.sort()
                            tiles_able_to_choose = self.player.deck
                            print("Tiles")
                            print(tiles_able_to_choose)
                            tiles_chosen=[]
                            prob = random.randint(1, 1)
                            if prob == 1 and len(self.player.picked_pieces) < 5:
                                print('Pick')
                                random.shuffle(tiles_able_to_choose)
                                piece=tiles_able_to_choose.pop()
                                tiles_chosen.append(piece)
                                self.player.picked_pieces.append(piece)
                                tiles_able_to_choose.sort()
                                cipher_tiles = self.sendDataPlayer(tiles_able_to_choose,self.next_player_key)
                                cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)
                                msg = {"action": "choose_tiles", "tiles": cipher_tiles, "chosen": cipher_chosen}

                            else:
                                print('Pass')
                                cipher_tiles = self.sendDataPlayer(tiles_able_to_choose,self.next_player_key)
                                cipher_chosen = self.sendDataPlayer(tiles_chosen,self.next_player_key)
                                msg = {"action": "choose_tiles", "tiles": cipher_tiles, "chosen": cipher_chosen}
                            print(tiles_able_to_choose)
                            print(tiles_chosen)
                            print(msg)
                            self.sendData(pickle.dumps(msg))
                elif data["next_action"] == "create_tuple":
                    tiles_chosen = self.receiveDataPlayer(data["chosen"], self.previous_player_key)
                    tiles_chosen = list(filter(lambda a: a != 0, tiles_chosen))
                    print('Pseudonyms: ' + str(tiles_chosen) + '\n')

                    ls_pseud = []
                    ls_keys = []
                    cipher_keys_ls = []

                    if 'keys' in data:
                        for i in data['keys']:
                            ls_keys.append(self.receive_data_cena_fixe(i, self.previous_player_key))

                    for t in self.player.picked_pieces:
                        if t in tiles_chosen:
                            private_key = generate_keys(key_size=1024)
                            self.player.priv_keys.append(private_key)
                            public_key = private_key.public_key()
                            new_pub_key = key_to_bytes(public_key)
                            # new_pub_key = self.sendListData(new_pub_key, self.next_player_key)
                            ls_pseud.append(t)
                            ls_keys.append(new_pub_key)
                            tiles_chosen.remove(t)
                            tiles_chosen.append(t)

                    for i in ls_keys:
                        cipher_keys_ls.append(self.sendListData(i, self.next_player_key))


                    print('Player pseudonyms:' + str(ls_pseud) + '\n')
                    send_pseus = self.sendDataPlayer(tiles_chosen, self.next_player_key)
                    cipher_pseu_ls = self.sendDataPlayer(ls_pseud, self.next_player_key)
                    print("REFRESH")
                    print(tiles_chosen)
                    msg = {"action": "receive_tiles", "chosen":send_pseus, 'keys' : cipher_keys_ls, 'refresh': tiles_chosen}
                    self.sendData(pickle.dumps(msg))


                elif data["next_action"] == "play":
                    if 'cheating' in data:
                        print('REAL PIECE' + str(self.player.real_piece))
                        self.player.insertInHand(self.player.real_piece)
                        self.player.real_piece = 0
                        self.player.updatePieces(1)
                        print(self.player.hand)
                    if "piece" in data:
                        print('Picked tile from stock -> ' + str(data["piece"]).strip())
                        self.player.insertInHand(data["piece"])
                    msg = self.player.play()
                    self.sendData(pickle.dumps(msg))

                elif data["next_action"] == "decrypt_tile":
                    if self.player.host:
                        print(self.player.ls_cipher)
                        print(self.player.dct_pseu_key)
                        for k in self.player.dct_pseu_key:
                            ps = decrypt_aes_pycrypto(self.player.dct_pseu_key[k], data["chosen"])
                            if self.player.decodeable(ps):
                                msg = {"action": "tile_decrypted", "tile":k}
                                self.sendData(pickle.dumps(msg))
                    elif "second" in data:
                        for k in self.player.dct_oldcipher_key:
                            if k == decrypt_aes_pycrypto(self.player.dct_oldcipher_key[k], data["chosen"]):
                                msg = {"action": "decrypt_tile", "tile":k}
                                self.sendData(pickle.dumps(msg))
                    else:
                        for k in self.player.dct_oldcipher_key:
                            if k == decrypt_aes_pycrypto(self.player.dct_oldcipher_key[k], self.player.ls_cipher[data["chosen"]-1]):
                                msg = {"action": "decrypt_tile", "tile":k}
                                self.sendData(pickle.dumps(msg))

                elif data["next_action"] == "decrypt_deck":
                    if self.player.host:
                        tiles_chosen = data["chosen"]
                        ls_keys = []
                        for i in data['keys']:
                            ls_keys.append(self.receive_data_cena_fixe(i, self.next_player_key))
                        pseu_ls = []
                        for l in tiles_chosen:
                            for k in self.player.dct_pseu_key:
                                ps = decrypt_aes_pycrypto(self.player.dct_pseu_key[k], l)
                                if self.player.decodeable(ps):
                                    pseu_ls.append(k)
                                    break

                        msg = {"action": "get_piece", "chosen":pseu_ls, 'keys' : ls_keys}
                        self.sendData(pickle.dumps(msg))

                    elif "counter" in data:

                        tiles_chosen = data["chosen"]
                        ls_keys = []
                        for i in data['keys']:
                            ls_keys.append(self.receive_data_cena_fixe(i, self.next_player_key))
                        pseu_cipher_ls = []
                        for l in tiles_chosen:
                            for k in self.player.dct_oldcipher_key:
                                print(self.player.dct_oldcipher_key[k])
                                print(str(l) + '\n' + str(len(l)))
                                if k == decrypt_aes_pycrypto(self.player.dct_oldcipher_key[k], l):
                                    pseu_cipher_ls.append(k)
                                    break
                        print(tiles_chosen)
                        print(ls_keys)
                        cipher_keys_ls = []
                        for i in ls_keys:
                            cipher_keys_ls.append(self.sendListData(i, self.previous_player_key))
                        msg = {"action": "get_deck_to_decrypt", "chosen":pseu_cipher_ls, 'keys' : cipher_keys_ls}
                        self.sendData(pickle.dumps(msg))
                    else:
                        tiles_chosen = self.receiveDataPlayer(data["chosen"], self.next_player_key)
                        tiles_chosen = list(filter(lambda a: a != 0, tiles_chosen))
                        ls_keys = []
                        for i in data['keys']:
                            ls_keys.append(self.receive_data_cena_fixe(i, self.next_player_key))

                        print(self.player.dct_oldcipher_key)
                        pseu_cipher_ls = []

                        for l in tiles_chosen:
                            for k in self.player.dct_oldcipher_key:
                                if k == decrypt_aes_pycrypto(self.player.dct_oldcipher_key[k], self.player.ls_cipher[l-1]):
                                    pseu_cipher_ls.append(k)
                                    break
                        print(pseu_cipher_ls)
                        cipher_keys_ls = []
                        for i in ls_keys:
                            cipher_keys_ls.append(self.sendListData(i, self.previous_player_key))
                        msg = {"action": "get_deck_to_decrypt", "chosen":pseu_cipher_ls, 'keys' : cipher_keys_ls}
                        self.sendData(pickle.dumps(msg))

        elif action == "end_game":
            winner = data["winner"]
            if data["winner"] == self.player.name:
                winner = Colors.BRed + "YOU" + Colors.Color_Off
            else:
                winner = Colors.BBlue + winner + Colors.Color_Off
                for l in self.player.hand:
                    self.player.score=self.player.score + int(l.values[0].value) + int(l.values[1].value)
                if self.player.score >= 50:
                    self.player.score = random.randint(1, 5)
            print(Colors.BGreen+"End GAME, THE WINNER IS: " + winner)
            msg = {"action": "game_ended", "score": self.player.score, "number" : len(self.player.hand)}
            self.sendData(pickle.dumps(msg))

        elif action == "cli2cli":
            # enviar mensagem para o manager a dizer com quem quer comunicar
            msg={"action":"start_cli2cli","source":self.player.name,"dest":self.players_nicks[random.randint(0, len(self.players_nicks)-1)]}
            self.sendData(pickle.dumps(msg))

        elif action == "wait":
            print(data["msg"])
            if self.player.wait_value == 1:
                msg = {"action": "get_deck_to_encrypt"}
                self.sendData(pickle.dumps(msg))
            if self.game_over_flag == 1:
                msg = {"action": "disconnect"}
                self.sendData(pickle.dumps(msg))

        elif action == "src_dh_cli2cli":
            print (data["msg"])
            # Start diffie-hellman negotiation through manager
            g = 11
            p = 593
            random.seed()
            self.cli2cli_a_src = random.randint(10000, 999999)
            A = (g**self.cli2cli_a_src) % p
            msg={"action" : "dst_dh_cli2cli","msg":str(A)}
            self.sendData(pickle.dumps(msg))

        elif action == "dst_dh_cli2cli":
            # calculate the public key on the destination side
            g = 11
            p = 593
            random.seed()
            self.cli2cli_a_dst = random.randint(10000, 999999)
            A = (g**self.cli2cli_a_dst) % p
            msg={"action" : "src_dh2_cli2cli","msg":str(A)}

            keyServer = data["msg"]
            secretDst = (int(keyServer)**self.cli2cli_a_dst) % p
            print('Shared secret: %s' % secretDst)

            # secret needs to have 16 characters
            secret=bytes (self.pad16Str(str (secretDst)),'utf-8')
            self.cli2cli_secret_dest=secret

            self.sendData(pickle.dumps(msg))

        elif action =="src_dh2_cli2cli":
            p = 593
            keyServer = data["msg"]
            secretSource = (int(keyServer)**self.cli2cli_a_src) % p
            print('Shared secret: %s' % secretSource)

            # secret needs to have 16 characters
            secret=bytes (self.pad16Str(str (secretSource)),'utf-8')
            self.cli2cli_secret_src=secret

            msg_to_client={"msg":"What's up !!! Message from another player."}
            # encrypton with AES and the message needs to be a multiple of 16
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            encd = aes.encrypt(self.pad16Bytes(pickle.dumps(msg_to_client)))

            msg_to_manager={"action":"msg_to_dest_cli2cli","msg":encd}

            self.sendData(pickle.dumps(msg_to_manager))

        elif action == "msg_from_src_cli2cli":
            msg=data["msg"]
            iv = 16 * b'\0'
            aes = AES.new(self.cli2cli_secret_dest, AES.MODE_CBC, iv)
            data1 = aes.decrypt(msg)
            data2=pickle.loads(data1)
            print("Message received: ",data2["msg"])

            msg={"action":"close_cli2cli"}
            self.sendData(pickle.dumps (msg))


        elif action =="disconnect":
            self.sock.close()
            print("PRESS ANY KEY TO EXIT ")
            sys.exit(0)

        elif action == "get_ready":
            msg = {"action": "send_scores"}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_game_scores":
            self.player.scores = data["scores"]
            print("My Score: "+ str(self.player.score))
            print('Game Over')
            biggest_score = 0
            for l in self.player.scores:
                if l>biggest_score:
                    biggest_score=l
                if(l == self.player.score) and self.game_over_flag == 0:
                    self.game_over_flag = 0
                else:
                    print('Others score: {}'.format(l))
            final_points = biggest_score - self.player.score
            if final_points < 0:
                final_points = 0
            print('Final Points: ' + str(final_points))
            msg = {"action": "game_over", "score": self.player.scores}
            self.sendData(pickle.dumps(msg))

        elif action == "award_points":
            msg = {'action': 'award', 'score' : self.player.score}
            self.sendData(pickle.dumps(msg))

        elif action == 'game_over':
            for sc in data['score']:
                print('Score: ' + str(sc))
            exit(0)



a = client('localhost', 50000)
