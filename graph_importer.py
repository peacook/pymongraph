from mongraph import MongoGraph
from pymongo.bulk import BulkOperationBuilder
from pymongo.errors import DuplicateKeyError
import pymongo
import socket
import re
import time


class GraphImporter(MongoGraph):
    def __init__(self, host='localhost', port=27017, username='', password='', dbname='mongraph'):
        MongoGraph.__init__(self, host, port, username, password, dbname)

        self._not_browse_fields = [
            'whois',
            'domain-siblings',
            'dns-resolutions',
            'observed-subdomains',
            'detected-urls',
            'detected-downloaded',
            'undetected-downloaded',
            'detected-referrer',
            'undetected-referrer',
            'detected-communicating',
            'undetected-communicating',
        ]

    def _get_host_by_addr(self, ipaddress):
        try:
            hostname = socket.gethostbyaddr(ipaddress)
            return True, hostname[0]
        except Exception, message:
            return False, message

    def _is_ipaddress(self, resource):
        validIP = re.compile(
            '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        if validIP.match(resource):
            return True
        else:
            return False

    def _get_resource_name(self, resource):
        """
        Depend on resource is dictionary or a string to get resource name
        :param resource:
        :return:
        """
        if type(resource) == dict:
            return resource.keys()[0]
        else:
            return resource

    def _extract_data_and_save(self, resource, depth=0, is_malicious=False):
        resource_data = self._get_resource_name(resource)

        # Check resource is None or not
        if resource_data is None:
            return

        if type(resource) is not dict:
            return

        print 'Process resource: %s' % ('-' * depth) + resource_data

        if self._is_ipaddress(resource_data):
            first_node = self.insert_vertex(label='ip', identify={'address': resource_data},
                                            data={'address': resource_data})
        else:
            first_node = self.insert_vertex(label='domain', identify={'name': resource_data},
                                            data={'name': resource_data})

        if 'observed-subdomains' in resource[resource_data].keys():
            for subdomain in resource[resource_data]['observed-subdomains']:
                second_resource_data = self._get_resource_name(subdomain['domain'])
                second_node = self.insert_vertex('domain', {'name': second_resource_data},
                                                 {'name': second_resource_data})

                rel = self.insert_edge(first_node, second_node, 'observed')
                self._extract_data_and_save(subdomain['domain'], depth + 1)

        if 'dns-resolutions' in resource[resource_data].keys():
            for resolve in resource[resource_data]['dns-resolutions']:
                if not self._is_ipaddress(resource_data):
                    second_resource_data = self._get_resource_name(resolve['ipaddress'])
                    second_node = self.insert_vertex('ip', {'address': second_resource_data},
                                                     {'address': second_resource_data})

                    rel = self.insert_edge(first_node, second_node, 'assign', {'date': resolve['date']})
                    self._extract_data_and_save(resolve['ipaddress'], depth + 1)
                else:
                    second_resource_data = self._get_resource_name(resolve['domain'])
                    second_node = self.insert_vertex('domain', {'name': second_resource_data},
                                                     {'name': second_resource_data})

                    rel = self.insert_edge(first_node, second_node, 'assign', {'date': resolve['date']})
                    self._extract_data_and_save(resolve['domain'], depth + 1)

        legitimate_list = ['undetected-downloaded', 'undetected-communicating', 'undetected-referrer']
        malicious_list = ['detected-downloaded', 'detected-communicating', 'detected-referrer']
        total = 0
        malicious_prop = 0
        for detect_element in (legitimate_list + malicious_list):
            if detect_element in resource[resource_data]:
                for detect in resource[resource_data][detect_element]:

                    data_hash = detect['hash'] if 'hash' in detect else ''
                    data_time = detect['datetime'] if 'datetime' in detect else ''
                    data_prob = detect['prob'] if 'prob' in detect else ''

                    total += 1
                    detected, checker = map(int, data_prob.strip().split('/'))
                    malicious_prop += 1.0 * detected / checker

                    if detect_element in legitimate_list:
                        detect_node = self.insert_vertex('legitimate', {'hash': data_hash},
                                                         {
                                                             'hash': data_hash,
                                                             'datetime': data_time,
                                                             'probability': data_prob
                                                         }
                                                         )
                        self.insert_edge(first_node, detect_node, 'trusted')
                    else:
                        detect_node = self.insert_vertex('malicious', {'hash': data_hash},
                                                         {
                                                             'hash': data_hash,
                                                             'datetime': data_time,
                                                             'probability': data_prob
                                                         })
                        self.insert_edge(first_node, detect_node, 'threat')

        # Update property probability of detected domain from checker
        if total != 0:
            self.update_vertex(first_node, {
                'detected_prop': 1.0 * malicious_prop / total
            })
        else:
            self.update_vertex(first_node, {
                'detected_prop': 0
            })

        # Whois record
        if 'whois' in resource[resource_data] and 'contacts' in resource[resource_data]['whois']:
            whois_contact = resource[resource_data]['whois']['contacts']
            contact_list = ['admin', 'tech', 'registrant']
            for dept in contact_list:
                if (dept in whois_contact and whois_contact[dept] is not None and 'email' in whois_contact[dept]):
                    contact = whois_contact[dept]
                    whois_data = {}
                    for attr in contact:
                        whois_data[attr] = contact[attr]

                    self.insert_node(first_node, 'owner', 'belongTo', {'email': contact['email']}, whois_data)

        for field in resource[resource_data].keys():
            if field not in self._not_browse_fields or field == resource_data:
                if type(resource[resource_data][field]) is list:
                    index = 0
                    addition_data = {}
                    for field_elements in resource[resource_data][field]:
                        addition_data[field + '_' + str(index)] = field_elements
                        index += 1
                    self.update_vertex(first_node, addition_data)
                elif type(resource[resource_data][field]) is dict:
                    addition_data = {}
                    for field_elements in resource[resource_data][field]:
                        addition_data[field + '_' + field_elements] = resource[resource_data][field][field_elements]
                    self.update_vertex(first_node, addition_data)
                else:
                    self.update_vertex(first_node, {field: resource[resource_data][field]})

    def _bulk_extract(self, resource, depth=0, is_malicious=False):

        # Mutate bypass
        VERTICES = []
        EDGES = []

        resource_data = self._get_resource_name(resource)

        # Check resource is None or not
        if resource_data is None:
            return VERTICES, EDGES

        if type(resource) is not dict:
            return VERTICES, EDGES

        print 'Process resource: %s' % ('-' * depth) + resource_data

        if self._is_ipaddress(resource_data):
            first_node_id = 'ip_address:%s' % resource_data
            FIRST_NODE = {'_id': first_node_id, '__type': 'ip', 'address': resource_data}
        else:
            first_node_id = 'domain_name:%s' % resource_data
            FIRST_NODE = {'_id': first_node_id, '__type': 'domain', 'name': resource_data}

        if 'observed-subdomains' in resource[resource_data].keys():
            for subdomain in resource[resource_data]['observed-subdomains']:
                second_resource_data = self._get_resource_name(subdomain['domain'])
                second_node_id = 'domain_name:%s' % second_resource_data
                SECOND_NODE = {'_id': second_node_id, '__type': 'domain', 'name': second_resource_data}

                EDGES.append({'nodes': [first_node_id, second_node_id], '__type': 'observed'})
                tmp_vertices, tmp_edges = self._bulk_extract(subdomain['domain'], depth + 1)
                VERTICES.extend(tmp_vertices)
                EDGES.extend(tmp_edges)
                VERTICES.append(SECOND_NODE)

        if 'dns-resolutions' in resource[resource_data].keys():
            for resolve in resource[resource_data]['dns-resolutions']:
                if not self._is_ipaddress(resource_data):
                    second_resource_data = self._get_resource_name(resolve['ipaddress'])
                    second_node_id = 'ip_address:%s' % second_resource_data
                    SECOND_NODE = {'_id': second_node_id, '__type': 'ip', 'address': second_resource_data}

                    EDGES.append({'nodes': [first_node_id, second_node_id], '__type': 'assign',
                                  'date': [resolve['date']]})
                    tmp_vertices, tmp_edges = self._bulk_extract(resolve['ipaddress'], depth + 1)
                    VERTICES.extend(tmp_vertices)
                    EDGES.extend(tmp_edges)
                else:
                    second_resource_data = self._get_resource_name(resolve['domain'])
                    second_node_id = 'domain_name:%s' % second_resource_data
                    SECOND_NODE = {'_id': second_node_id, '__type': 'domain', 'name': second_resource_data}

                    EDGES.append({'nodes': [first_node_id, second_node_id], '__type': 'assign',
                                  'date': [resolve['date']]})
                    tmp_vertices, tmp_edges = self._bulk_extract(resolve['domain'], depth + 1)
                    VERTICES.extend(tmp_vertices)
                    EDGES.extend(tmp_edges)
                VERTICES.append(SECOND_NODE)

        legitimate_list = ['undetected-downloaded', 'undetected-communicating', 'undetected-referrer']
        malicious_list = ['detected-downloaded', 'detected-communicating', 'detected-referrer']
        total = 0
        malicious_prop = 0
        for detect_element in (legitimate_list + malicious_list):
            if detect_element in resource[resource_data]:
                for detect in resource[resource_data][detect_element]:

                    data_hash = detect['hash'] if 'hash' in detect else ''
                    data_time = detect['datetime'] if 'datetime' in detect else ''
                    data_prob = detect['prob'] if 'prob' in detect else ''

                    total += 1
                    detected, checker = map(int, data_prob.strip().split('/'))
                    malicious_prop += 1.0 * detected / checker

                    if detect_element in legitimate_list:
                        detect_node = 'legitimate_hash:%s' % data_hash
                        VERTICES.append({'_id': detect_node, '__type': 'legitimate', 'hash': data_hash,
                                         'datetime': data_time,
                                         'probability': data_prob})
                        EDGES.append({'nodes': [first_node_id, detect_node], '__type': 'trusted'})
                    else:
                        detect_node = 'malicious_hash:%s' % data_hash
                        VERTICES.append({'_id': detect_node, '__type': 'malicious', 'hash': data_hash,
                                         'datetime': data_time,
                                         'probability': data_prob})
                        EDGES.append({'nodes': [first_node_id, detect_node], '__type': 'threat'})

        # Update property probability of detected domain from checker
        if total != 0:
            FIRST_NODE['detected_prop'] = 1.0 * malicious_prop / total
        else:
            FIRST_NODE['detected_prop'] = 0.0

        # Whois record
        # if 'whois' in resource[resource_data] and 'contacts' in resource[resource_data]['whois']:
        #     whois_contact = resource[resource_data]['whois']['contacts']
        #     contact_list = ['admin', 'tech', 'registrant']
        #     for dept in contact_list:
        #         if (dept in whois_contact and whois_contact[dept] is not None and 'email' in whois_contact[dept]):
        #             contact = whois_contact[dept]
        #             whois_data = {}
        #             for attr in contact:
        #                 whois_data[attr] = contact[attr]
        #
        #             self.insert_node(first_node, 'owner', 'belongTo', {'email': contact['email']}, whois_data)

        for field in resource[resource_data].keys():
            if field not in self._not_browse_fields or field == resource_data:
                if type(resource[resource_data][field]) is list:
                    index = 0
                    for field_elements in resource[resource_data][field]:
                        FIRST_NODE[field + '_' + str(index)] = field_elements
                elif type(resource[resource_data][field]) is dict:
                    for field_elements in resource[resource_data][field]:
                        FIRST_NODE[field + '_' + field_elements] = resource[resource_data][field][field_elements]
                else:
                    FIRST_NODE[field] = resource[resource_data][field]

        VERTICES.append(FIRST_NODE)

        return VERTICES, EDGES

    def import_from_json(self, json_data, is_malicious=False):
        """

        :param is_malicious:
        :type json_data: the crawled data from some source, which format to Cyradar json standard. Type: json
        """
        begin_time = time.time()
        VERTICES, EDGES = self._bulk_extract(json_data, is_malicious=True)
        print "Total time to extract: %f seconds" % (time.time() - begin_time)

        begin_time = time.time()
        print "Importing vertices"
        BOB_vertices = self.vertices_collection.initialize_unordered_bulk_op()
        for i in VERTICES:
            BOB_vertices.find({'_id': i['_id']}).upsert().update_one({'$set': i})
        BOB_vertices.execute()
        print "Total time to import vertices: %f seconds" % (time.time() - begin_time)

        begin_time = time.time()
        print "Import edges"

        self.edges_collection.create_index([('nodes', pymongo.ASCENDING)])
        BOB_edge = self.edges_collection.initialize_ordered_bulk_op()
        for i in EDGES:
            BOB_edge.find({'nodes': i['nodes']}).upsert().update_one({'$set': i})
        BOB_edge.execute()

        print "Total time to import edges: %f seconds" % (time.time() - begin_time)
