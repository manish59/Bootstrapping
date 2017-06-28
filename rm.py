def _rm(string):
    new_string = ""
    for i in string:
        if i == " " or i=="\n":
            continue
        else:
            new_string = new_string + i
    return new_string
