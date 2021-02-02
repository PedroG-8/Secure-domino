import os
import sys
import PyKCS11


def get_abs_path(rel_path: str, is_dir: bool = False):
    """

    :param rel_path: relative path
    :param is_dir:
    :return:
    """

    path = os.path.realpath(rel_path)

    assert os.path.exists(path), "File does not exist in specified path!"
    assert not is_dir or os.path.isdir(path), "Expected directory, got file"

    return path


if __name__ == '__main__':
    # Testing if needed
    ...
