import asyncio

class Database:
    @classmethod
    async def connect(cls):
        # Simulate async connection creation
        await asyncio.sleep(0.1)
        return cls()

    async def disconnect(self):
        # Simulate async disconnection cleanup
        await asyncio.sleep(0.1)

    def query(self) -> str:
        # Simulated DB query response
        return "Fake DB query result: all clear."
