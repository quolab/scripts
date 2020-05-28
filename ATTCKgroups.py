# Refererences:
# https://medium.com/threat-hunters-forge/automate-the-creation-of- \
# att-ck-navigator-group-layer-files-with-python-3b16a11a47cf
# https://attackcti.readthedocs.io/en/latest/attackcti_functions.html
# https://www.mitre.org/capabilities/cybersecurity/overview/ \
# cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via

from attackcti import attack_client
from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, Encases, Tag, Tagged
from pyquo.models import File, Malware, URL, IpAddress, Certificate
from pyquo.magicparser import MagicParser
import requests
import PyPDF2
import argparse
import io
import os

requests.packages.urllib3.disable_warnings()


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

    def __get_full_intrusion_set(self, groups, filter):
        for group in groups:
            if filter and group['name'].lower() not in filter:
                continue
            print(' |- Adding Intrusion Set for \"%s\"' % (group['name']))
            group_set = {'techniques':
                         self.__c.get_techniques_used_by_group(group),
                         'softwares':
                         self.__c.get_software_used_by_group(group)}
            group_set.update(group)
            self.__intrusion_set[group['name']] = group_set

    def get_intrusion_set(self, filter=[]):
        print('[+] Fetching MITRE ATT&CK Intrusion Set')
        groups = self.__c.get_groups()
        groups = self.__c.remove_revoked(groups)
        self.__get_full_intrusion_set(groups, filter)

    def __get_and_parse_PDF(self, url):
        indicators = []
        p = MagicParser()
        try:
            r = requests.get(url, verify=False)
        except requests.exceptions.SSLError:
            return indicators
        except requests.exceptions.ConnectionError:
            return indicators
        if r.status_code != 200:
            return indicators
        if r.headers['content-type'] != 'application/pdf':
            return indicators
        # Get text from each PDF page and parse it with MagicParser
        with io.BytesIO(r.content) as pdf_file:
            reader = PyPDF2.PdfFileReader(pdf_file, strict=False)
            try:
                title = reader.getDocumentInfo().title
                for page in reader.pages:
                    text = page.extractText()
                    indicators += p.parse(text)
            except PyPDF2.utils.PdfReadError:
                return indicators
        # Store PDF as a file, concretize it and then add it to indicator list
        if not title:
            title = os.path.basename(url)
        f = File.upload(r.content, filename=title)
        f.save()
        indicators.append(f)
        # Concretize indicators unless phantoms (Hashes or IP ranges)
        # pyquo not supporting facets yet we need to filter on type and id
        for indicator in indicators:
            if type(indicator) == File or type(indicator) == Certificate:
                continue
            if type(indicator) == IpAddress and '/' in indicator.id:
                continue
            indicator.save()
        return indicators

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

    def __map_ATTCK_IDs_as_tags(self, case, techniques):
        # Collect ATT&CK techniques and tag appropriately
        for tech_id, _ in self.__get_ATTCK_IDs(techniques):
            tags = [t for t in Tag.filter() if tech_id in t.name]
            for tag in tags:
                ref = Tagged(source=case, target=tag).save()
                print(' |-', ref)

    def __map_external_reference(self, case, intrusion_set):
        # Create folders with external references
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
            print(' |--', ref)
            # If URL leads to PDF attempt to parse indicators from it
            for indicator in self.__get_and_parse_PDF(url.id):
                ref = Encases(source=folder, target=indicator).save()
                print(' |---', ref)

    def __map_malware_set(self, case, softwares):
        # XXX deal with x_mitre_aliases
        # XXX maybe also good to keep the rescription -> url if any
        for _, name in self.__get_ATTCK_IDs(softwares, ['malware']):
            malware = Malware(name).save()
            ref = Encases(source=case, target=malware).save()
            print(' |-', ref)

    def map_to_quolab(self):
        for name in self.__intrusion_set:
            print('[+] Mapping Intrusion Set \"%s\" to QuoLab' % (name))
            # Create an adversary case with as name the group value
            case_name = name
            aliases = self.__intrusion_set[name]['aliases']
            aliases.remove(case_name)
            if aliases:
                case_name += ' (a.k.a. %s)' % (', '.join(aliases))
            description = self.__intrusion_set[name]['description']
            case = Case(name=case_name, description=description,
                        flavor='case', type='adversary').save()
            # Extract ATT&CK IDs and tag the case with it
            techniques = self.__intrusion_set[name]['techniques']
            self.__map_ATTCK_IDs_as_tags(case, techniques)
            # Walk through external references to create folders
            # Parse indicators from reports and encase to folders
            self.__map_external_reference(case, self.__intrusion_set[name])
            # Extract ATT&CK softwares IDs relative to malware
            # and create Malware facts to be enclosed to the case
            softwares = self.__intrusion_set[name]['softwares']
            self.__map_malware_set(case, softwares)


if __name__ == '__main__':
    description = 'QuoLab importer for MITRE ATT&CK groups intrusiton set'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='https://qlab.quo')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    p.add_argument('--filter', type=str, help='apt1,...')
    args = p.parse_args()

    username, password = args.creds.split(':')
    q = QuoLab(args.host, username, password)

    filter = []
    if args.filter:
        filter = [f.lower() for f in args.filter.split(',')]

    a = ATTCKgroups()
    a.get_intrusion_set(filter)
    a.map_to_quolab()
