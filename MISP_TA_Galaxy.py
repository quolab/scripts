from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, Encases, Tag, Tagged
from pyquo.models import File, URL, IpAddress, Certificate
from pyquo.magicparser import MagicParser
import requests
import PyPDF2
import json
import argparse
import io
import os

requests.packages.urllib3.disable_warnings()

MISP_TA_GALAXY_URL = 'https://raw.githubusercontent.com/MISP/'\
                     'misp-galaxy/master/clusters/threat-actor.json'

TARGET_CATEGORIES_MAPPING = {
     'Automotive': '2510 Automobiles & Components',
     'Business': '2020 Commercial & Professional Services',
     'Civil society': '9010 Political',
     'Cryptocurrency': '40 Financials',
     'Education': '9050 Education',
     'Energy': '10 Energy',
     'Finance': '40 Financials',
     'Financial': '40 Financials',
     'Government': '90 Government',
     'Healthcare': '35 Health Care',
     'High-Tech': '45 Information Technology',
     'Intergovernmental': '90 Government',
     'Media and Entertainment': '2540 Media',
     'Military': '9020 Defense',
     'Pharmaceuticals': '3520 Pharmaceuticals, Biotechnology & Life Sciences',
     'Private sector': '20 Industrials',
     'Retail': '2550 Retailing',
     'Scientific Research': '9060 Research',
     'Services': '2530 Consumer Services',
     'Telecommunications': '50 Telecommunication Services',
     'Travel': '2030 Transportation'}


class QuoLab(object):

    def __init__(self, url, username, password):
        self.connect(url, username, password)

    def connect(self, url, username, password):
        auth = UserAuthenticator(username=username,
                                 password=password)
        session.Session(base_url=url,
                        global_session=True,
                        auth=auth)


class MISP_TA_Galaxy(object):

    def __init__(self):
        self.__groups = None
        self.__coverage = {}

    def __get_galaxy(self):
        try:
            r = requests.get(MISP_TA_GALAXY_URL)
        except requests.exceptions.ConnectionError:
            return []
        if r.status_code != 200:
            return []
        j = json.loads(r.content)
        return j['values']

    def get_TA_galaxy(self):
        print('[+] Fetching MISP Threat Actor Galaxy')
        self.__groups = self.__get_galaxy()
        print(' |- Total of %d actors fetched' % (len(self.__groups)))

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

    def __search_toplevel_tags(self, cat):
        tags = []
        for tag in [t for t in Tag.filter() if cat in t.name]:
            name = tag.name.split(' ')
            if len(name[0]) != 2:
                continue
            tags.append(tag)
        return tags

    def __map_to_tags(self, cat):
        tags = [t for t in Tag.filter()
                if t.name == TARGET_CATEGORIES_MAPPING.setdefault(cat, [])]
        return tags

    def __map_target_category_as_tag(self, case, cats):
        for cat in cats:
            tags = self.__map_to_tags(cat)
            if not tags:
                tags = self.__search_toplevel_tags(cat)
            if not tags:
                print(' ! Unknown category \"%s\"' % (cat))
            for tag in tags:
                ref = Tagged(source=case, target=tag).save()
                print(' |-', ref)

    def __map_external_references(self, case, refs):
        count = 1
        # Create a forlder for each reference
        for url in refs:
            folder = Case(name='Ref #%d' % (count),
                          description=None,
                          flavor='folder',
                          type='investigation').save()
            ref = Encases(source=case, target=folder).save()
            print(' |-', ref)
            url = URL(url).save()
            ref = Encases(source=folder, target=url).save()
            print(' |--', ref)
            # If URL leads to PDF, attempt to parse indicators from it
            for indicator in self.__get_and_parse_PDF(url.id):
                ref = Encases(source=folder, target=indicator).save()
                print(' |---', ref)
            count += 1

    def map_to_quolab(self):
        for group in self.__groups:
            name = group['value']
            print('[+] Mapping TA \"%s\" to QuoLab' % (name))
            # Create an adversary case
            case_name = name
            if 'meta' in group and 'synonyms' in group['meta']:
                case_name += ' (a.k.a. %s)' % (
                    ', '.join(group['meta']['synonyms']))
            description = None
            if 'description' in group:
                description = group['description']
            case = Case(name=case_name, description=description,
                        flavor='case', type='adversary').save()
            # Attempt to map cfr-target-category as tags
            if 'meta' in group and 'cfr-target-category' in group['meta']:
                self.__map_target_category_as_tag(
                    case, group['meta']['cfr-target-category'])
            # Walk through external references to create folders
            # Parse indicators from reports and encase to folders
            if 'meta' in group and 'refs' in group['meta']:
                self.__map_external_references(case, group['meta']['refs'])


if __name__ == '__main__':
    description = 'QuoLab importer for the MISP threat-actor galaxy'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='https://qlab.quo')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    args = p.parse_args()

    username, password = args.creds.split(':')
    q = QuoLab(args.host, username, password)

    m = MISP_TA_Galaxy()
    m.get_TA_galaxy()
    m.map_to_quolab()
