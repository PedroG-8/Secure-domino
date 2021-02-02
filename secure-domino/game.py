from deck_utils import Deck, Player


class Game:
    def __init__(self, max_players):
        self.deck = Deck()
        print("Deck created \n", self.deck)
        self.max_players = max_players
        self.nplayers = 0
        self.players = []
        self.player_index = 0
        self.init_distribution = True
        self.next_action = "choose_tiles"
        self.started = False
        self.all_ready_to_play = False
        self.scores = []
        self.encr = []

    def checkDeadLock(self):
        return all([player.nopiece for player in self.players])

    def allPlayersWithPieces(self):
        return 28 - len(self.deck.deck) == 15

    def currentPlayer(self):
        return self.players[self.player_index]

    def nextPlayer(self):
        self.player_index += 1
        if self.player_index == self.max_players:
            self.player_index = 0
        return self.players[self.player_index]

    def previousPlayer(self):
        self.player_index -=1
        if self.player_index == -1:
            self.player_index = self.max_players-1
        return self.players[self.player_index]

    def addPlayer(self, name, socket, pieces):
        self.nplayers += 1
        assert self.max_players >= self.nplayers
        player = Player(name, socket, pieces)
        print(player)
        self.players.append(player)

    def hasHost(self):
        return len(self.players) > 0

    def hasPlayer(self, name):
        for player in self.players:
            if name == player.name:
                return True
        return False

    def isFull(self):
        return self.nplayers == self.max_players
        
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

    def toJson(self):
        msg = {"next_player": self.players[self.player_index].name,
               "nplayers": self.nplayers, "next_action": self.next_action,
               "scores": self.scores}
        msg.update(self.deck.toJson())
        return msg
