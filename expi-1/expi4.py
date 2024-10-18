import hashlib
import itertools
from math import *
from tqdm import tqdm

target_hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

possible_char = ['0', '5', '8', 'Q', 'W', 'I', 'N', '+']

table = {'Q': 'q', 'W': 'w', 'I': 'i', 'N': 'n', '5': '%', '8': '(', '0': '=', '+': '*'}

def sha1_crack(target_hash, possible_char):
    for length in range(1, 9):
        pbar = tqdm(itertools.permutations(possible_char, length), 
                    total=factorial(len(possible_char)) // factorial(len(possible_char) - length),
                    desc=f'length: {length}')
        for permutation in itertools.permutations(possible_char, length):
            password = ''.join(permutation)

            for mask in itertools.product([True, False], repeat=length):
                password_tmp = list(password)
                for i in range(len(mask)):
                    if mask[i]:
                        password_tmp[i] = table[password_tmp[i]]

                password_tmp = ''.join(password_tmp)
                # print(password_tmp)
                # pbar.set_description(f'length {length}, trying {password_tmp}')
            
                hash_object = hashlib.sha1(password_tmp.encode())
                hash_hex = hash_object.hexdigest()
                
                if hash_hex == target_hash:
                    return password_tmp
    
    return None


password = sha1_crack(target_hash, possible_char)

if password:
    print(f"Answer found: {password}")
else:
    print("No answer found")
