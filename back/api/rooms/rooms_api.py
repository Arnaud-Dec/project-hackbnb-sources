from flask import jsonify, Blueprint, request, send_from_directory
from sqlalchemy.orm import joinedload
from .rooms_models import Room
from database.init import db

rooms_api = Blueprint('rooms', __name__)


@rooms_api.route('/', methods=['GET'])
def list_rooms():
   """
   List all available rooms with given category
   """

   if "category" in request.args:
      category = request.args["category"]
      # D1
      rooms = Room.query.filter_by(category=category).all()
   else:
      rooms = Room.query.all()

   return jsonify([room.to_dict() for room in rooms])


@rooms_api.route('/<room_id>', methods=['GET'])
def get_room_details(room_id: str):
   """
   Get room details
   """

   room = Room.query.options(joinedload(Room.host_user)).filter_by(id=room_id).first()
   if not room:
      return {'error': 'Room not found'}, 404

   return jsonify(room.to_dict())


@rooms_api.route('/<room_id>/picture')
def send_report(room_id: str):
   return send_from_directory('pictures', room_id + ".jpg")
