from typing import List
from database.init import db
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

class Room(db.Model):
    __tablename__ = 'rooms'

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column()
    city: Mapped[str] = mapped_column()
    price: Mapped[float] = mapped_column()
    picture: Mapped[str] = mapped_column()
    category: Mapped[str] = mapped_column(index=True)
    description: Mapped[str] = mapped_column()
    host_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    host_user: Mapped["User"] = relationship('User', back_populates="rooms")
    bookings: Mapped[List["Booking"]] = relationship(back_populates="room")

    def __repr__(self):
        return f'<Room {self.id!r}>'
    
    def to_dict(self):
        output = {
            "id": self.id,
            "title": self.title,
            "city": self.city,
            "price": self.price,
            "picture": self.picture,
            "category": self.category,
            "description": self.description,
        }

        if self.host_user:
            # D5
            output["host"] = self.host_user.to_public_dict()

        return output
