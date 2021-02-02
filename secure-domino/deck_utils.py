import sys
import random
import Colors
from ciphers import encrypt_aes_pycrypto, decrypt_aes_pycrypto

class Player:
    def __init__(self, name, socket, pieces_per_player=None):
        self.name = name
        self.socket = socket
        self.hand = []
        self.num_pieces = 0
        self.score = 0
        self.host = False
        self.pieces_per_player = pieces_per_player
        self.max_pieces = 5
        self.ready_to_play = False
        self.in_table = []
        self.deck = []
        self.nopiece = False
        self.scores = []
        self.wait_value = 0
        #dicionarios para armazenar a chave valor das cifras do deck
        self.dct_pseu_key = {}
        self.dct_oldcipher_key = {}
        self.picked_pieces = []
        self.priv_keys = []
        self.ls_cipher = []
        self.real_piece = 0

    def __str__(self):
        return str(self.toJson())

    def printPseudonym(self):
        a = ""
        for piece in self.deck:
            a += str(piece.printPseudonym())
        return a

    def toJson(self):
        return {"name": self.name, "hand": self.hand, "score": self.score, "scores": self.scores}

    def isHost(self):
        return self.host

    def pickPiece(self):
        if not self.ready_to_play and self.num_pieces == self.pieces_per_player:
            self.ready_to_play = True
        random.shuffle(self.deck)
        peca = self.deck.pop()
        #self.insertInHand(piece)
        return {"action": "get_piece_from_pseu", "piece": peca}

    def updatePieces(self, i):
        self.num_pieces += i

    def canPick(self):
        return self.num_pieces < self.pieces_per_player

    def insertInHand(self, piece):
        self.num_pieces += 1
        self.hand.append(piece)
        self.hand.sort(key=lambda p: int(p.values[0].value)+int(p.values[1].value))

    def checkifWin(self):
        print("Winner ", self.num_pieces == 0)
        return self.hand == []

    def piece_in_ls(self, piece, ls):
        side_to_play1 = piece.values[0].value
        side_to_play2 = piece.values[1].value
        for i in ls:
            side_1 = i.values[0].value
            side_2 = i.values[1].value
            if side_1 == side_to_play1 and side_2 == side_to_play2:
                return True
            elif side_1 == side_to_play2 and side_2 == side_to_play1:
                return True
        return False

    def play(self):
        res = {}
        if self.in_table == []:
            print("Empty table")
            piece = self.hand.pop(-1)
            self.updatePieces(-1)
            res = {"action": "play_piece", "piece": piece, "edge": 0, "win": False}
        else:
            for p in self.hand:
                if self.piece_in_ls(p, self.in_table):
                    res = {"action": "play_piece", "warning" : "player is cheating"}
                    print(Colors.BRed + 'Some player played one of my pieces (' + Colors.Color_Off + str(p).strip() + Colors.BRed + ')' + Colors.Color_Off)
                    return res
            edges = self.in_table[0].values[0].value, self.in_table[len(
                self.in_table) - 1].values[1].value
            max = 0
            index = 0
            edge = None
            flip = False
            # get if possible the best piece to play and the correspondent assigned edge
            for i, piece in enumerate(self.hand):
                aux = int(piece.values[0].value) + int(piece.values[1].value)
                if aux > max:
                    if int(piece.values[0].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = True
                        edge = 0
                    elif int(piece.values[1].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = False
                        edge = 0
                    elif int(piece.values[0].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = False
                        edge = 1
                    elif int(piece.values[1].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = True
                        edge = 1
            # if there is a piece to play, remove the piece from the hand and check if the orientation is the correct
            if edge is not None:
                piece = self.hand.pop(index)
                if flip:
                    piece.flip()
                self.updatePieces(-1)
                res = {"action": "play_piece", "piece": piece,
                       "edge": edge, "win": self.checkifWin()}
            # if there is no piece to play try to pick a piece, if there is no piece to pick pass
            else:
                if self.hand == []:
                    res = {"action": "pass_play", "piece": None,
                           "edge": edge, "win": self.checkifWin()}
                    return res
                elif len(self.deck) > 0:
                    prob_cheating = random.randint(1, 40)
                    if prob_cheating == 1:
                        piece = Piece(str(edges[1]), str(random.randint(0, 6)))
                        self.real_piece = self.hand.pop(-1)
                        self.updatePieces(-1)
                        res = {"action": "play_piece", "piece": piece,
                               "edge": edge, "win": self.checkifWin()}
                    else:
                        res = self.pickPiece()
                else:
                    res = {"action": "pass_play", "piece": None,
                           "edge": edge, "win": self.checkifWin()}
                    return res
        print("To play -> "+str(piece))
        return res


    def randN(self):
        ls = ['a', 'b', 'c',  'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',]

        s=""
        for i in range(0,16):
            r = random.randint(0,25)
            s = s + ls[r]
        return s

    def decodeable(self, data):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def encrypt_deck_host(self, deck):

        pseu=[]
        for i in deck:
            pseu.append(str(i))

        #pseu = ["0", "1", "2", "3", "4", "5"]
        # aux = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
        #        "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27"]
        self.dct_pseu_key = {}
        # dct_newpsew_cipher = {}

        for l in pseu:
            self.dct_pseu_key[l] = self.randN()

        #random.shuffle(aux)
        ls_cipher = []

        for i in pseu:
            ls_cipher.append(encrypt_aes_pycrypto(i,self.dct_pseu_key[i]))

        random.shuffle(ls_cipher)

        self.ls_cipher = ls_cipher

        return ls_cipher

    def encrypt_deck_player(self, ls):

        aux = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
            "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27"]

        self.dct_oldcipher_key = {}
        #dct_newpsew_cipher = {}
        ls_cipher = []
        for k in ls:
            self.dct_oldcipher_key[k] = self.randN()
        for k in self.dct_oldcipher_key:
            ls_cipher.append(encrypt_aes_pycrypto(k,self.dct_oldcipher_key[k]))

        self.ls_cipher = ls_cipher
        return ls_cipher

class Piece:
    values = []
    pseudonym = 0

    def __init__(self, first, second, index=0):
        self.values = [SubPiece(first), SubPiece(second)]
        self.hashed = self.hashh(first, second)
        self.tileIndex = index

    def __str__(self):
        return " {}:{}".format(str(self.values[0]), str(self.values[1]))

    def printPseudonym(self):
        return " {}".format(str(self.pseudonym))

    def flip(self):
        self.values = [self.values[1], self.values[0]]

    def hashh(self, f, s):
        self.r = random.randint(1, 10000)
        return (int(f) + int(s) + 3) * int(self.r)

    def setPseudonym(self, newValue):
        self.pseudonym = newValue


class SubPiece:
    value = None

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "\033[1;9{}m{}\033[0m".format(int(self.value)+1, self.value)


class Deck:

    deck = []
    pseu_deck = []
    used_tiles = []
    used_pseu = []
    total_score = 0
    aux_pseudonyms = []

    def __init__(self, pieces_per_player=5):
        ls_hash = []
        with open('pieces', 'r') as file:
            pieces = file.read()
        i = 0
        for piece in pieces.split(","):
            piece = piece.replace("\n", "")
            piece = piece.replace(" ", "").split("-")
            peca = Piece(piece[0], piece[1], i)
            ls_hash.append(peca.hashed)
            self.deck.append(peca)
            self.aux_pseudonyms.append(i+1)

            i += 1
        ls_hash = sorted(ls_hash)

        for piece in self.deck:
            i = 0
            self.total_score = self.total_score + int(piece.values[0].value) + int(piece.values[1].value)
            for hashValue in ls_hash:
                if piece.hashed == hashValue:
                    piece.setPseudonym(i)
                i = i+1
            self.pseu_deck.append(piece.pseudonym)
        self.npieces = len(self.deck)
        self.pieces_per_player = pieces_per_player
        self.in_table = []

    def __str__(self):
        a = ""
        for piece in self.deck:
            a += str(piece)
        return a

    def printPseudonym(self):
        a = ""
        for piece in self.deck:
            a += str(piece.printPseudonym())
        return a

    def getPieceFromPseu(self, pseu):
        for i in range(0,len(self.deck)):
            if self.pseu_deck[i] == pseu:
                return self.deck[i]
        return 0

    def removePiece(self, pseu):
        for l in self.deck:
            if l.pseudonym == pseu:
                self.used_tiles.append(l)
                self.used_pseu.append(pseu)
                self.deck.remove(l)
                self.pseu_deck.remove(pseu)
                break

    def toJson(self):
        return {"npieces": self.npieces, "pieces_per_player": self.pieces_per_player, "in_table": self.in_table, "deck": self.pseu_deck, "pseu_deck": self.aux_pseudonyms}
