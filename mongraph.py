from pymongo import MongoClient
from exceptions import ValueError, UnboundLocalError
import bson


class MongoGraph:
    def __init__(self, host='localhost', port=27017, username='', password='', dbname='mongraph'):
        """
        Constructor of class MongoGraph
        :param host:
        :param port:
        :param username:
        :param password:
        :param dbname:
        """
        self._mongo_client = MongoClient(host=host, port=port)
        self._mongo_dbname = self._mongo_client[dbname]
        self.vertices_collection = self._mongo_dbname['vertices']
        self.edges_collection = self._mongo_dbname['edge']
        self._type_dependency = {
            'domain': {'name'},
            'ip': {'address'}
        }

    def change_collection(self, vertices_collection='vertices', edge_collection='edge'):
        """

        :param vertices_collection: vertices collection name
        :param edge_collection: edge collection name
        """
        self.vertices_collection = vertices_collection
        self.edges_collection = edge_collection

    def insert_vertex(self, label='domain', identify=None, data={}):
        """
        Insert only ONE vertex dependency
        :param label: some kind of label such as 'domain', 'ip', 'legitimate', 'malicious', 'whois'...
        :param data: additional attributes of vertex
        :return:
        """
        # Check dependency
        if label not in self._type_dependency.keys():
            raise UnboundLocalError('%s is not in label set' % label)

        if not self._type_dependency[label].issubset(set(data.keys())):
            raise ValueError('Vertex attributes are not contain dependencies')

        data['__type'] = label

        # Check duplicate
        if identify is not None and type(identify) == dict:
            identify['__type'] = label
            vertex = self.vertices_collection.find_one(identify)
            if vertex is not None:
                return vertex['_id']

        new_vertex = self.vertices_collection.insert_one(data)
        return new_vertex.inserted_id

    def insert_edge(self, first_node, second_node, label='resolve', data={}):
        """

        Insert ONE edge, which mean connect two vertex
        :param identify:
        :param first_node: first vertex object
        :param second_node: second vertex object
        :param label: label of edge
        :param data: additional attributes of edge
        :return:
        """
        data['__type'] = label


        # Validate nodes
        if type(first_node) is not bson.objectid.ObjectId or type(second_node) is not bson.objectid.ObjectId:
            raise ValueError('Wrong type of node')
        data['first_node'] = first_node
        data['second_node'] = second_node

        # Check duplicate data
        edge = self.edges_collection.find_one({
            'first_node': first_node,
            'second_node': second_node,
            '__type': label
        })
        if edge is not None:
            return edge['_id']

        new_edge = self.edges_collection.insert_one(data)
        return new_edge.inserted_id

    def insert_node(self, destination, vertex_label='domain', edge_label='resolve', vertex_identify=None, vertex_data={}, edge_data={}):
        """

        Insert one node - create a vertex then connect it with an exists vertex
        :param destination:
        :param vertex_label:
        :param edge_label:
        :param vertex_identify:
        :param vertex_data:
        :param edge_data:
        :return:
        """
        source = self.insert_vertex(vertex_label, vertex_identify, vertex_data)
        connection = self.insert_edge(source, destination, edge_label, edge_data)
        return (source, connection, destination)

    def delete_node(self, node, filter=None):

        """
        Remove a vertex and all edges which connect with it
        :param node:
        :param filter:
        :return:
        """
        if filter is None:
            filter = {}

        if node is None:
            node = self.vertices_collection.find_one(filter)
            if '_id' in node.keys():
                node = node['_id']
            else:
                return False

        delete_result = self.vertices_collection.remove({'_id': node})
        self.edges_collection.remove({
            '$or': [
                {'first_node': node},
                {'second_node': node}
            ]
        })
        if delete_result['n'] > 0:
            return True
        else:
            return False

    def delete_edge(self, edge):
        """
        Remove a edge, which mean disconnect connection of 2 vertices
        :param edge:
        :return:
        """
        delete_result = self.edges_collection.remove({'_id': edge})
        if delete_result['n'] > 0:
            return True
        else:
            return False

    def update_vertex(self, vertex, data={}):
        """
        Find and update a vertex
        :param vertex:
        :param data:
        """
        self.vertices_collection.update_one({'_id', vertex}, {'$set': data})

    def update_edge(self, edge, data={}):
        """
        Find and update a edge
        :param edge:
        :param data:
        """
        self.edges_collection.update_one({'_id', edge}, {'$set': data})

    


