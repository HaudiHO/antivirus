import os
import sys
from flask import Flask, render_template, jsonify, request
from scanner import scan_all_targets
from remediation import remediate_file as fix_target

def resource_path(relative_path: str) -> str:
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base_path, relative_path)

app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static")
)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    return jsonify(scan_all_targets())

@app.route("/fix", methods=["POST"])
def fix():
    data = request.get_json(force=True)
    target = data.get("target")
    return jsonify(fix_target(target))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)