# B105: hardcoded_password_string
# Note https://github.com/PyCQA/bandit/issues/551 may hide this error in python 3
def foo(password):
    if password == "1234":
        return 0
