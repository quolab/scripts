# Refererences:
# https://medium.com/threat-hunters-forge/automate-the-creation-of- \
# att-ck-navigator-group-layer-files-with-python-3b16a11a47cf
# https://attackcti.readthedocs.io/en/latest/attackcti_functions.html
# https://www.mitre.org/capabilities/cybersecurity/overview/ \
# cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via

from attackcti import attack_client
from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, Tag, Tagged, Malware, Encases, URL
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


class ATTCKgroups(object):

    def __init__(self):
        self.__c = attack_client()
        self.__intrusion_set = {}

    def __map(self, groups):
        for group in groups:
            print(' |- Adding Intrusion Set for \"%s\"' % (group['name']))
            group_set = {'techniques':
                         self.__c.get_techniques_used_by_group(group),
                         'softwares':
                         self.__c.get_software_used_by_group(group)}
            group_set.update(group)
            self.__intrusion_set[group['name']] = group_set

    def get_intrusion_set(self):
        print('[+] Fetching MITRE ATT&CK Intrusion Set')
        groups = self.__c.get_groups()
        groups = self.__c.remove_revoked(groups)
        self.__map(groups)

    def __get_reference_URLs(self, attck_set):
        urls = []
        for reference in attck_set['external_references']:
            if reference['source_name'] == 'mitre-attack':
                continue
            if 'url' not in reference:
                continue
            urls.append((reference['url'],
                         reference['source_name'],
                         reference['description']))
        return urls

    def __get_ATTCK_IDs_from_refs(self, name, references):
        ids = []
        for reference in references:
            if reference['source_name'] != 'mitre-attack':
                continue
            ids.append((reference['external_id'], name))
        return ids

    def __get_ATTCK_IDs(self, attck_set, filter=[]):
        ids = []
        for s in attck_set:
            if filter and s['type'] not in filter:
                continue
            name = s['name']
            references = s['external_references']
            ids += self.__get_ATTCK_IDs_from_refs(name, references)
        return ids

    def map_to_quolab(self):
        for name in self.__intrusion_set:
            print('[+] Mapping Intrusion Set \"%s\" to QuoLab' % (name))
            # Create an adversary case with as name the group value
            description = self.__intrusion_set[name]['description']
            case = Case(name=name, description=description,
                        flavor='case', type='adversary').save()
            # XXX deal with threat actor aliases
            # Create folders with the external references
            intrusion_set = self.__intrusion_set[name]
            for reference in self.__get_reference_URLs(intrusion_set):
                url, source, description = reference
                folder = Case(name=source,
                              description=description,
                              flavor='folder',
                              type='investigation').save()
                ref = Encases(source=case, target=folder).save()
                print(' |-', ref)
                url = URL(url).save()
                ref = Encases(source=folder, target=url).save()
                print(' |-', ref)
            # Collect ATT&CK techniques and tag appropriately
            techniques = self.__intrusion_set[name]['techniques']
            for tech_id, _ in self.__get_ATTCK_IDs(techniques):
                tags = [t for t in Tag.filter() if tech_id in t.name]
                for tag in tags:
                    ref = Tagged(source=case, target=tag).save()
                    print(' |-', ref)
            # Collect malware names and encase them
            softwares = self.__intrusion_set[name]['softwares']
            for _, name in self.__get_ATTCK_IDs(softwares, ['malware']):
                malware = Malware(name).save()
                ref = Encases(source=case, target=malware).save()
                print(' |-', ref)
            # XXX deal with x_mitre_aliases


if __name__ == '__main__':
    description = 'QuoLab importer for MITRE ATT&CK groups intrusiton set'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='https://qlab.quo')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    args = p.parse_args()

    username, password = args.creds.split(':')
    q = QuoLab(args.host, username, password)

    a = ATTCKgroups()
    a.get_intrusion_set()
    a.map_to_quolab()
