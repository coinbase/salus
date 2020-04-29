# https://semgrep.live/WRE

class User:
    def __init__(self, id):
        self.id = id


def route(user_id):
    user = User(1)
    if user.id == user.id:
        return '200'
    else:
        return '404'