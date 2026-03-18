from flask import Flask, render_template, jsonify, request
from scanner import scan_all_targets
from remediation import fix_target

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    result = scan_all_targets()
    return jsonify(result)

@app.route("/fix", methods=["POST"])
def fix():
    data = request.get_json(force=True)
    target = data.get("target")
    return jsonify(fix_target(target))

if __name__ == "__main__":
    # debug=False, чтобы не торчал дебаггер
    app.run(host="127.0.0.1", port=5050, debug=False)