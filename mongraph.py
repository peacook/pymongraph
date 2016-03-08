from pymongo import MongoClient

class MongoGraph:
    def __init__(self, host='localhost', port=27017, username='', password='', dbname='mongraph'):
        self._mongo_client = MongoClient(host=host, port=port)
        self._mongo_dbname = self._mongo_client[dbname]
        self.vertex_collection = self._mongo_dbname['vertex']
        self.edge_collection = self._mongo_dbname['edge']


    def change_collection(self, vertex_collection='vertex', edge_collection='edge'):
        self.vertex_collection = vertex_collection
        self.edge_collection = edge_collection