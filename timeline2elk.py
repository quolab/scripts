import argparse
import websocket
import base64
import json
import requests
import elasticsearch
try:
    import thread
except ImportError:
    import _thread as thread


class ElasticSearchConnector(object):
    def __init__(self, elkhost):
        self.__es = elasticsearch.Elasticsearch([{'host': elkhost}])
        self.__es_index = 'quolab'

        self.__es_map_event = {
            'event': {
                'properties': {
                    'body': {
                        'properties': {
                            'timestamp': {
                                'type': 'date',
                                'format': 'epoch_millis'
                            }
                        }
                    }
                }
            }
        }

        self.__doc_methods = {
            'event': self.__es_map_event}

        self.__build_index()

    def __build_index(self):
        if not self.__es.indices.exists(self.__es_index):
            self.__es.indices.create(self.__es_index)
            for tag in self.__doc_methods:
                mapping = self.__doc_methods[tag]
                self.__es.indices.put_mapping(index=self.__es_index,
                                              doc_type=tag,
                                              body=mapping,
                                              include_type_name=True)

    def index_doc(self, doc):
        self.__es.index(index=self.__es_index,
                        doc_type=doc['name'],
                        body=doc)


class QuoLabWS(object):

    def __init__(self, qhost, qcreds, timelines):
        self.__qhost = qhost
        self.__qcreds = qcreds
        self.__get_timelines(timelines)
        self.__elk = None

    def __get_timelines(self, timeline):
        user, password = self.__qcreds.split(':')
        d = requests.get('http://%s/v1/timeline' % (self.__qhost),
                         auth=(user, password))
        j = json.loads(d.content)
        ids = map(lambda t: t['id'], j['records'])
        if timeline:
            self.__timeline_ids = set(ids).intersection(timeline.split(','))
        else:
            self.__timeline_ids = ids
        if not self.__timeline_ids:
            raise RuntimeError('No timeline selected')

    def set_elk_sink(self, elkhost):
        self.__elk = ElasticSearchConnector(elkhost)

    def connect(self):
        auth = base64.b64encode(bytes(self.__qcreds, 'utf-8')).decode()
        header = ['Authorization: Basic %s' % (auth)]
        self.ws = websocket.WebSocketApp("ws://%s/v1/socket" % (self.__qhost),
                                         header=header,
                                         on_message=self.on_message,
                                         on_error=self.on_error,
                                         on_open=self.on_open,
                                         on_close=self.on_close)
        self.ws.run_forever()

    def on_message(self, msg):
        print('\n[Websocket Message]\n')
        j = json.loads(msg)
        print(json.dumps(j, sort_keys=True, indent=4))
        if not self.__elk:
            return
        # Skipping non event messages
        if j['name'] != 'event':
            return
        # Indexing the rest
        t = float(j['body']['timestamp'])
        j['body']['timestamp'] = int(t * 1000)
        self.__elk.index_doc(j)

    def on_error(self, err):
        print('[Websocket Error] ', err)

    def __ws_bind_req(self, tid):
        return json.dumps({
                            "attach": {
                                "ns": "activity-stream",
                                "name": "event",
                                "cid": "%s" % (tid)
                            },
                            "body": {
                                "composition": {
                                    "catalog": {
                                        "facets": {
                                            "display": True
                                        },
                                        "object": "object"
                                    }
                                }
                            },
                            "cid": "activity-stream-event-%s" % (tid),
                            "name": "bind",
                            "ns": "link/binding"
                            })

    def on_open(self):
        def run(*args):
            for tid in self.__timeline_ids:
                r = self.__ws_bind_req(tid)
                self.ws.send(r)
        thread.start_new_thread(run, ())

    def on_close(self):
        print('[Websocket Closed]')
        self.ws.close()


if __name__ == '__main__':
    description = 'Track QuoLab timeline events and dump them to ELK'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='quolab host')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    p.add_argument('--elk', type=str, help='elk host')
    p.add_argument('--timelines', type=str, help='timeline ID, ...')
    p.add_argument('--debug', action='store_true')
    args = p.parse_args()

    if args.debug:
        websocket.enableTrace(True)

    q = QuoLabWS(args.host, args.creds, args.timelines)
    if args.elk:
        q.set_elk_sink(args.elk)
    q.connect()
