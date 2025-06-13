from dataclasses import dataclass
from fake_database import Database  # Replace with your actual DB type

@dataclass
class AppContext:
    db: Database
