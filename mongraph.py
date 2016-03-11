from pymongo import MongoClient
from exceptions import ValueError, UnboundLocalError
import bson
import json


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
        # TODO: Implement authenticate
        self._mongo_client = MongoClient(host=host, port=port)
        self._mongo_dbname = self._mongo_client[dbname]
        self.vertices_collection = self._mongo_dbname['vertices']
        self.edges_collection = self._mongo_dbname['edge']
        self._type_dependency = {
            'domain': {'name'},
            'ip': {'address'},
            'legitimate': {'hash'},
            'malicious': {'hash'},
        }

    def _get_vertex_details(self, vertices):
        """
        Get full vertex data from vertex object ID
        :param vertices:
        :return:
        """
        if type(vertices) is bson.objectid.ObjectId:
            return self.vertices_collection.find_one(vertices)

        if type(vertices) in [list, set]:
            vertices_data = []
            for vertex in vertices:
                vertices_data.append(self.vertices_collection.find_one(vertex))

            return vertices_data
        return None

    def _get_edge_details(self, edges):
        """
        Get full edge data from edge object ID
        :param edges:
        :return:
        """
        if type(edges) is bson.objectid.ObjectId:
            return self.edges_collection.find_one(edges)

        if type(edges) in [list, set]:
            edges_data = []
            for edge in edges:
                edges_data.append(self.edges_collection.find_one(edge))
            return edges_data
        return None

    def change_collection(self, vertices_collection='vertices', edge_collection='edge'):
        """

        :param vertices_collection: vertices collection name
        :param edge_collection: edge collection name
        """
        self.vertices_collection = vertices_collection
        self.edges_collection = edge_collection

    def insert_vertex(self, label='domain', identify=None, data=None):
        """
        Insert only ONE vertex dependency
        :param label: some kind of label such as 'domain', 'ip', 'legitimate', 'malicious', 'whois'...
        :param data: additional attributes of vertex
        :return:
        """
        # Check dependency
        if data is None:
            data = {}
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

    def insert_edge(self, first_node, second_node, label='resolve', data=None):
        """

        Insert ONE edge, which mean connect two vertex
        :param first_node: first vertex object
        :param second_node: second vertex object
        :param label: label of edge
        :param data: additional attributes of edge
        :return:
        """
        if data is None:
            data = {}
        data['__type'] = label
        print "Before assign", data
        # Validate nodes
        if type(first_node) is not bson.objectid.ObjectId or type(second_node) is not bson.objectid.ObjectId:
            raise ValueError('Wrong type of node')
        data['first_node'] = first_node
        data['second_node'] = second_node
        print "After assign", data
        # Check duplicate data
        edge = self.edges_collection.find_one({
            'first_node': first_node,
            'second_node': second_node,
            '__type': label
        })
        print data, edge
        if edge is not None:
            return edge['_id']

        new_edge = self.edges_collection.insert_one(data)
        return new_edge.inserted_id

    def insert_node(self, destination, vertex_label='domain', edge_label='resolve', vertex_identify=None,
                    vertex_data=None, edge_data=None):
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
        if edge_data is None:
            edge_data = {}
        if vertex_data is None:
            vertex_data = {}
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

    def update_vertex(self, vertex, data=None):
        """
        Find and update a vertex
        :param vertex:
        :param data:
        """
        if data is None:
            data = {}
        self.vertices_collection.update_one({'_id': vertex}, {'$set': data})

    def update_edge(self, edge, data=None):
        """
        Find and update a edge
        :param edge:
        :param data:
        """
        if data is None:
            data = {}
        self.edges_collection.update_one({'_id': edge}, {'$set': data})

    def search_vertex(self, filter):
        """

        :param filter:
        :return:
        """
        vertex_set = []
        vertices = self.vertices_collection.find(filter)
        for vertex in vertices:
            vertex_set.append(vertex)

        return vertex_set

    def find_neighbors(self, vertex, get_details=False):
        """
        Find all vertices connected with a specify given vertex
        :param vertex:
        :param get_details:
        :return:
        """
        vertices = set()
        edges = self.edges_collection.find({
            '$or': [
                {'first_node': vertex},
                {'second_node': vertex}
            ]
        })

        for edge in edges:
            vertices.add(edge['first_node'])
            vertices.add(edge['second_node'])

        if get_details:
            return self._get_vertex_details(vertices), edges

        return vertices, edges

    def _explode_node(self, vertex, depth):
        """

        :param vertex:
        :param depth:
        :return:
        """
        EDGES = []
        VERTICES = []

        if depth > 0:
            neighbor_vertices, neighbor_edges = self.find_neighbors(vertex, get_details=False)

            for vertex in neighbor_vertices:
                VERTICES.append(vertex)
                exploded_vertices, exploded_edges = self._explode_node(vertex['_id'], depth - 1)
                VERTICES.extend(exploded_vertices)
                EDGES.extend(exploded_edges)

            for edge in neighbor_edges:
                EDGES.append(edge)

        return set(VERTICES), set(EDGES)

    def build_graph(self, root_vertex, filter=None, depth=4):
        """

        :param root_vertex:
        :param filter:
        :param depth:
        :return:
        """
        if filter is None:
            filter = {}
        edges = []
        vertices = []

        if root_vertex is None:
            root_vertex = self.vertices_collection.find_one(filter)
            if root_vertex is None:
                return None
            root_vertex = root_vertex['_id']

        for d in xrange(depth):
            vertices, edges = self._explode_node(root_vertex, 4)

        return json.dumps({
            'graph': {
                'vertices': vertices,
                'edges': edges
            }
        })
