from typing import List
from hashlib import md5
from database.init import db
from sqlalchemy.orm import Mapped, mapped_column, relationship

class User(db.Model):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column()
    rooms: Mapped[List["Room"]] = relationship(back_populates="host_user")

    def __repr__(self):
        return f'<User {self.email!r}>'
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
        }

    # D5
    def to_public_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    def set_password(self, clear_password: str):
        self.password_hash = md5(clear_password.encode("utf-8")).hexdigest()
    
    def is_valid_password(self, clear_password: str) -> bool:
        clear_password_hash = md5(clear_password.encode("utf-8")).hexdigest()
        return clear_password_hash == self.password_hash
