import os
from random import choice

def generate_random_name(length=50):
    charset  = "azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890"
    return "".join([choice(charset) for i in range(length)])

def generate_random_path(folder):
    charset  = "azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890"
    path = "{0}/{1}".format(folder, generate_random_name())
    while os.path.exists(path):
        path = "{0}/{1}".format(folder, generate_random_name())
    return path
