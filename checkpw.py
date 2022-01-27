#!/usr/bin/env python3

some_string = "FooBar123!"

def is_it_secure(some_string):

    print("must be longer than 6")
    if len(some_string) < 6:
        return False
    #break apart the string into chars
    char_list = list(some_string)
    print("must contain a special")
            special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', "\{", "\}", "<", ">", "-", '+', '[', ']', "|", "."]
    if not contains_special(char_list, special_chars):
        return False
    print("must container a upper")
    if not contains_upper(char_list):
        return False
    print("must container an int")
    if not contains_int(char_list):
        return False
    #finally
    print("no spaces allowed >:(")
    if contains_no_space(char_list):
        return True
    else:
        return False

def contains_special(list_of_chars, special_chars):
    for char in list_of_chars:
        if char in special_chars:
            return True
    return False

def contains_upper(list_of_chars):
    for char in list_of_chars:
        if char.isupper():
            return True
    return False

def contains_int(list_of_chars):
    for char in list_of_chars:
        try:
            int(char)
            return True
        except:
            pass
    return False

def contains_no_space(list_of_chars):
    for char in list_of_chars:
        if char.isspace():
            return False
    return True

print(is_it_secure(some_string))