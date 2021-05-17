import string
import secrets


def generate_password():  # generate 8 character password randomly with each upper, lower, digit, special character
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special_char = ['@', '*', '#']
    password = ''.join(
        secrets.choice(upper) + secrets.choice(lower) + secrets.choice(digits) + secrets.choice(special_char)
        for i in range(2))

    return password
