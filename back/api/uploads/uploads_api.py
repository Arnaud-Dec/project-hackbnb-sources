import os
from flask import Blueprint, request, send_file, abort

uploads_api = Blueprint('uploads', __name__)

# D2
UPLOADS_DIR = os.path.realpath('uploads')

@uploads_api.route('/')
def get_upload():
   # D2
   name = request.args.get("name", "")
   safe_name = os.path.basename(name)
   target = os.path.realpath(os.path.join(UPLOADS_DIR, safe_name))
   if not target.startswith(UPLOADS_DIR + os.sep) or not os.path.isfile(target):
      abort(404)
   return send_file(target)
