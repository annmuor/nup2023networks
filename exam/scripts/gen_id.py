import random
import sys


def get_by_id(_id):
    random.seed(_id)
    v = []
    for _ in range(16):
        v.append(random.choice(
            ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'a', 'z', 'b', 'q', 'c',
             'd', 'e', 'f', 'w', '3', '4', '5', '6', '7', '8', '9', '0']))
    return "".join(v)


if __name__ == '__main__':
    print(get_by_id(int(sys.argv[1])))
