# Refererences:
# https://medium.com/threat-hunters-forge/automate-the-creation-of- \
# att-ck-navigator-group-layer-files-with-python-3b16a11a47cf
# https://attackcti.readthedocs.io/en/latest/attackcti_functions.html
# https://www.mitre.org/capabilities/cybersecurity/overview/ \
# cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via


from attackcti import attack_client
from pyquo import session
from pyquo.authenticator import UserAuthenticator
import argparse


class QuoLab(object):

    def __init__(self, url, username, password):
        self.connect(url, username, password)

    def connect(self, url, username, password):
        auth = UserAuthenticator(username=username,
                                 password=password)
        session.Session(base_url=url,
                        global_session=True,
                        auth=auth)

    def create_case(self):
        pass


class ATTCKgroups(object):

    def __init__(self):
        self.__c = attack_client()
        self.__intrusion_set = {}

    def __map(self, group):
        d = map(lambda g:
                {'group':
                    group,
                 'techniques':
                    self.__c.get_techniques_used_by_group(g),
                 'software':
                    self.__c.get_software_used_by_group(g)}, group)
        return d

    def get_intrusion_set(self):
        print('[+] Fetching MITRE ATT&CK Intrusion Set')
        groups = self.__c.get_groups()
        groups = self.__c.remove_revoked(groups)

        for group in groups:
            print('- Adding Intrusion Set for \"%s\"' % (group['name']))
            self.__intrusion_set[group['name']] = self.__map(group)

    def map_to_quolab(self, q):
        pass


if __name__ == '__main__':
    description = 'QuoLab importer for MITRE ATT&CK groups intrusiton set'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str, help='https://qlab.quo')
    p.add_argumetn('--creds', type=str, help='username:password')
    args = p.parse_args()

    username, password = args.creds.split(':')
    q = QuoLab(args.host, username, password)

    a = ATTCKgroups()
    a.get_intrusion_set()
    a.map_to_quolab(q)
