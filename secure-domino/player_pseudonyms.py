from smartcards import cc_functs as ccf
import csv
import os
from randomuser import RandomUser
import random
from urllib.error import HTTPError
import json
import asym_keys


# References
# [1] - https://www.geeksforgeeks.org/add-a-keyvalue-pair-to-dictionary-in-python/
# [2] - https://realpython.com/python-csv/
# [3] - https://docs.python.org/3/library/csv.html
# [4] - https://www.w3schools.com/python/python_file_handling.asp
# [5] - https://pypi.org/project/randomuser/


def get_burned_pseuds() -> list:
    """

    :return: List with all used pseudonyms
    """

    with open("used_pseudonyms.txt") as f:
        burned: list = f.read().split("\n")

    return burned


def add_to_burned_pseuds(pseudonym: str) -> bool:
    """
    Adds a given pseudonym to list of burned ones
    :return: True if operation was performed successfully, False otherwise
    """
    try:
        with open(os.path.realpath("used_pseudonyms.txt"), 'a') as f:  # [4]
            f.write(f"\n{pseudonym}")
        return True
    except IOError as e:
        print(e)
        return False


def add_player(pseudonym: str) -> bool:
    """

    :param pseudonym: New player will have this pseudonym
    :return: bool: True if successfully saves (pseudonym, signature(pseudonym)) in dictionary
        Constraints:
            If pseudonym exists in:
                used_pseudonyms.txt file;
                players dict;
                    Function raises UserWarning and ends
    """

    # Load data of current game
    with open("game_data.json", 'r') as f:
        main_data: dict = json.load(f)
    # Players and their pseudonyms of current game
    players: dict = main_data["players"]
    # Pseudonym -> public_key of owner
    public_keys: dict = main_data["public_keys"]
    # Pseudonym -> id serial number
    id_s: dict = main_data["id_s"]

    # Check constraints: if pseudonynm
    is_burned = pseudonym in get_burned_pseuds()
    is_being_used = pseudonym in players.keys()
    if is_burned or is_being_used:
        if is_burned:
            print("Warning! Pseudonym can't be used anymore")
        else:
            print("Warning! Pseudonym is being used")
        return False

    # New key value pair in dict - [1]
    input("Introduce cc in reader. [Enter]")
    players[pseudonym] = bytes.hex(
        ccf.sign_digital(
            bytes(pseudonym, 'utf-8')
        )
    )
    # Check CC was in place
    if players[pseudonym] is None:
        return False

    # Save player's public key
    public_keys[pseudonym] = bytes.hex(asym_keys.key_to_bytes(ccf.get_public_key()))
    if public_keys[pseudonym] is None:
        return False

    # Save player's serial number
    id_s[pseudonym] = ccf.get_id_serial_number()
    if public_keys[pseudonym] is None:
        return False

    input("CC can be removed safely. [Enter]")

    # Save in game_data.json
    with open("game_data.json", 'w') as f:
        json.dump(
            {
                "players": players,
                "public_keys": public_keys,
                "id_s": id_s
            }, f
        )

    return True


def award_points(pseudonym: str, points: int) -> bool:
    """

    :param pseudonym: Winner's pseudonym
    :param points: Points to award to winner
    :return: bool -> True if all steps are done successfully
        This function will:
            1 - forward all pseudonyms (keys) to used_pseudonyms (burn)
            2 - Verify winner(s) identity using:
                    given signature;
                    public key provided by cc in slot.
            3 - Award points to winner
                3.1 - Save key->value:(iD_serialNumber -> points) in identity_points.csv
    """

    # Load data of current game
    with open("game_data.json", 'r') as f:
        main_data: dict = json.load(f)
    # Players and their pseudonyms of current game
    players: dict = main_data["players"]
    # Pseudonym -> public_key of owner
    public_keys: dict = main_data["public_keys"]
    # Pseudonym -> id serial number
    id_s: dict = main_data["id_s"]

    # Error cases
    if pseudonym not in players.keys():
        print("Pseudonym doesn't exist in current game!")
        return False

    # 1
    for pseud in players.keys():
        add_to_burned_pseuds(pseud)

    # 2
    ccf.verify_digital(
        data=bytes(pseudonym, 'utf-8'),
        signature=bytes.fromhex(players[pseudonym]),
        public_key=asym_keys.bytes_to_key(bytes.fromhex(public_keys[pseudonym]))
    )

    # 3
    # Get id number
    serial_no = id_s[pseudonym]
    # Get current cc's points
    previous_points = int(
        get_id_points(id_number=serial_no)
    )
    set_id_points(serial_no, str(previous_points+points))

    return True


def get_csv(id_file_path) -> dict:
    """

    :param id_file_path: File path to be read
    :return: csv file content in dict form
    """
    with open(id_file_path) as id_file:
        # Get info from csv [2]
        cr = csv.reader(id_file, delimiter=',')
        # Transform it to a dict of id_serial_no -> points
        ids_list: list = [elem for elem in cr]
        ids: dict = {}
        for elem in ids_list:
            # Get not empty elements
            if elem != list():
                k, v = elem
                ids[k] = v

    return ids


def get_id_points(id_number) -> int:
    """
    Searches identity_points for the given identity and get its points
        1 - Get CC's authentication identity serial number
        2 - read id_p.csv to a dict
            2.1 - if id doesn't exist in dict, write new line with 0 points
    :return: d[serial_no]
    """

    id_file_path = os.path.realpath("identity_points.csv")

    ids: dict = get_csv(id_file_path)

    pts = ids.get(id_number)
    if pts is None:
        # Write new_line
        with open(id_file_path, 'w') as f:
            cw = csv.writer(f, delimiter=',')
            cw.writerows(ids.items())
            cw.writerow((id_number, 0))
        # Set points to 0
        pts = 0

    return pts


def set_id_points(id_number: str, new_points: str):
    """
    Sets the total points related to an identity
    :param id_number: identifier
    :param new_points: Updated points
    :return: void
                saves in csv file the provided info
    """

    id_file_path = os.path.realpath("identity_points.csv")

    lines: dict = get_csv(id_file_path=id_file_path)

    lines[id_number] = new_points

    # Write updated info in file
    with open(id_file_path, 'w') as f:
        cw = csv.writer(f, delimiter=',')  # [3]
        cw.writerows(lines.items())


def flush_game_data() -> bool:
    """
    Resets game_data.json
    :return:
    """
    try:
        with open("game_data.json", 'w') as f:
            json.dump(
                {
                    "players": {},
                    "public_keys": {},
                    "id_s": {}
                }, f
            )
    except IOError:
        return False

    return True


def random_username():
    try:
        return RandomUser().generate_users(1)[0].get_username()  # [5]
    except HTTPError:
        return f"player{random.randint(10000,100000)}"


if __name__ == '__main__':

    # --- Lets test this out ---
    # Test burned pseudonyms internal module (NOT for server/client)
    used_pseudonym = random_username()
    assert add_to_burned_pseuds(used_pseudonym)
    assert used_pseudonym in get_burned_pseuds()

    # Ensure json is of correct format:
    #  If last execution did not end properly it's probably not
    flush_game_data()

    # Adding a pseudonym for player1
    pseudonym = random_username()
    pseudonym2 = random_username()
    assert add_player(pseudonym)
    assert add_player(pseudonym2)

    # Awarding points to winner (performed by table manager at the end of the game)
    winner_points: int = 10
    assert award_points(pseudonym, winner_points)
    assert flush_game_data()
