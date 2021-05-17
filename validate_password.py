def is_check_none_space_length(pwd):
    return pwd is not None and ' ' not in pwd and 8 <= len(pwd) <= 16


def is_check_char(pwd):
    str_func = [str.isalpha, str.islower, str.isupper]
    result = []
    for item in str_func:
        if any(item(char) for char in pwd):
            result.append(True)
        else:
            result.append(False)
    return all(result)


def is_check_special_char(pwd):
    special_char = ['*', '.', '@', '!']
    return any(char for char in pwd if char in special_char)

