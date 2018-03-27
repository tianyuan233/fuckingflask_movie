from . import home


@home.route("/")
def index():
    return "<h1>HOME</h1>"
