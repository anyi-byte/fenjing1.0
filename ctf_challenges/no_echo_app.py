"""无回显 SSTI 靶场 — 模板会被渲染，但结果不返回给用户。"""

from flask import Flask, request

from jinja2 import Environment

app = Flask(__name__)
env = Environment()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        name = request.form.get("name", "")
        try:
            # 模板确实被渲染了，但结果被丢弃，不回显
            env.from_string("Hello " + name).render()
        except Exception:
            pass
        return "OK"
    return """
    <form method="POST">
        <input name="name" placeholder="your name">
        <button type="submit">Submit</button>
    </form>
    """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
